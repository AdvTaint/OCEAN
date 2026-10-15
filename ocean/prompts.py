"""Prompt formatting for screening and adversarial verification."""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import subprocess
import time
import traceback
import warnings
from collections import Counter, OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, Field
from tqdm import tqdm


from .config import (
    LOAD_BEARING_RULE,
    REVIEW_MODE,
    SINGLE_STAGE,
)
from .evidence import (
    _format_vec_counterevidence,
    _task_guard_annotations,
)
from .structures import (
    MultiSourcePathTask,
    SourceSubpath,
)
from .textutil import (
    _prompt_facts_for_subpath,
    _call_arguments,
    _meaningful_label,
    _target_function_code,
    _dedup_preserve_order,
    _json_schema_example_screening,
    _json_schema_example_verification,
    _normalize_space,
    _normalize_string_list,
    _safe_int,
    _safe_list,
    _stable_hash,
)
from .tpt import (
    _fact_signature,
    _sink_signature,
    _subpath_call_chain,
    _subpath_call_edges,
)




def _task_prompt_fact_count(task: MultiSourcePathTask) -> int:
    return sum(len(_prompt_facts_for_subpath(subpath)) for subpath in task.source_subpaths)


def _guard_registry(subpath: SourceSubpath) -> Tuple[OrderedDict[str, str], Dict[str, str]]:
    # Guards are plain control-condition strings (from control_dependence lists)
    # and carry no program-point position, so a guard listed for a sink may in
    # principle reference a point after the sink. Without position metadata no
    # per-sink dominance filtering is possible here; building one would require a
    # dominator analysis, which is deliberately out of scope.
    guard_to_id: OrderedDict[str, str] = OrderedDict()
    for fact in _prompt_facts_for_subpath(subpath):
        for guard in _safe_list(fact.get("controls")):
            normalized = _normalize_space(str(guard))
            if normalized and normalized not in guard_to_id:
                guard_to_id[normalized] = f"{subpath.subpath_id}-G{len(guard_to_id) + 1}"
    for sink in subpath.sinks:
        for guard in _safe_list(sink.get("controls")):
            normalized = _normalize_space(str(guard))
            if normalized and normalized not in guard_to_id:
                guard_to_id[normalized] = f"{subpath.subpath_id}-G{len(guard_to_id) + 1}"
    return guard_to_id, {guard: guard_id for guard, guard_id in guard_to_id.items()}


def _task_guard_registries(
    task: MultiSourcePathTask,
) -> Tuple[OrderedDict[str, str], Dict[str, OrderedDict[str, str]], Dict[str, Dict[str, str]]]:
    """Split guard dictionaries into task-shared and subpath-local scopes.

    A control condition appearing in several subpaths of the same task is the
    same evidence (guards are plain control-condition strings); printing it once
    with a TG id removes per-subpath duplication. Subpath-unique guards keep
    their SPx-Gn ids. Returns (shared guard->id, subpath_id -> local guard->id,
    subpath_id -> guard->id lookup).
    """
    per_subpath: List[Tuple[str, List[str]]] = []
    guard_spread: Dict[str, int] = {}
    for subpath in task.source_subpaths:
        texts: List[str] = []
        seen: Set[str] = set()
        for fact in _prompt_facts_for_subpath(subpath):
            for guard in _safe_list(fact.get("controls")):
                normalized = _normalize_space(str(guard))
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    texts.append(normalized)
        for sink in subpath.sinks:
            for guard in _safe_list(sink.get("controls")):
                normalized = _normalize_space(str(guard))
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    texts.append(normalized)
        per_subpath.append((subpath.subpath_id, texts))
        for text in texts:
            guard_spread[text] = guard_spread.get(text, 0) + 1

    multi = len(task.source_subpaths) > 1
    shared: OrderedDict[str, str] = OrderedDict()
    local: Dict[str, OrderedDict[str, str]] = {}
    lookup: Dict[str, Dict[str, str]] = {}
    for subpath_id, texts in per_subpath:
        local_to_id: OrderedDict[str, str] = OrderedDict()
        sub_lookup: Dict[str, str] = {}
        for text in texts:
            if multi and guard_spread.get(text, 0) > 1:
                if text not in shared:
                    shared[text] = f"TG{len(shared) + 1}"
                sub_lookup[text] = shared[text]
                continue
            if text not in local_to_id:
                local_to_id[text] = f"{subpath_id}-G{len(local_to_id) + 1}"
            sub_lookup[text] = local_to_id[text]
        local[subpath_id] = local_to_id
        lookup[subpath_id] = sub_lookup
    return shared, local, lookup


def _guard_ids(controls: Any, guard_lookup: Dict[str, str]) -> List[str]:
    result: List[str] = []
    for guard in _safe_list(controls):
        normalized = _normalize_space(str(guard))
        guard_id = guard_lookup.get(normalized)
        if guard_id and guard_id not in result:
            result.append(guard_id)
    return result






def _format_subpath_guards(
    guard_to_id: OrderedDict[str, str],
    annotations: Optional[Dict[str, str]] = None,
) -> str:
    if not guard_to_id:
        return "None"
    lines: List[str] = []
    for guard, guard_id in guard_to_id.items():
        line = f"{guard_id}: `{guard}`"
        annotation = (annotations or {}).get(guard)
        if annotation:
            line += f"  [{annotation}]"
        lines.append(line)
    return "\n".join(lines)


def _format_subpath_facts(
    subpath: SourceSubpath,
    mode: str,
    guard_lookup: Dict[str, str],
    facts_override: Optional[Sequence[Dict[str, Any]]] = None,
) -> str:
    facts = list(facts_override) if facts_override is not None else _prompt_facts_for_subpath(subpath)
    if not facts:
        # Caller omits the section entirely when there is nothing to render.
        return ""
    lines: List[str] = []
    for fact in facts:
        fact_id = fact.get("fact_id", "F?")
        event_kind = fact.get("event_kind", "FACT")
        function_name = fact.get("function", "[unknown]")
        code = str(fact.get("code") or "")
        guard_ids = _guard_ids(fact.get("controls"), guard_lookup)
        path_step = _safe_int(fact.get("path_step"), -1)
        start_byte = _safe_int(fact.get("start_byte"), -1)
        parameter_index = fact.get("parameter_index")
        abstract_object = fact.get("abstract_object")
        branch_signature = _safe_list(fact.get("branch_signature"))

        evidence_status = _meaningful_label(fact.get("evidence_status"))
        effect_source = _meaningful_label(fact.get("effect_source"))
        effect_strength = _meaningful_label(fact.get("effect_strength"))
        effect_kind = _meaningful_label(fact.get("effect_kind"))
        object_identity = _meaningful_label(fact.get("object_identity"))
        ordering_note = _meaningful_label(fact.get("ordering_note"))

        if mode == "ultra":
            suffix: List[str] = []
            if parameter_index is not None:
                suffix.append(f"arg={parameter_index}")
            if abstract_object:
                suffix.append(f"obj={abstract_object}")
            if object_identity and object_identity != "explicit":
                suffix.append(f"identity={object_identity}")
            if guard_ids:
                suffix.append("guards=" + ",".join(guard_ids))
            if branch_signature:
                suffix.append("branch=" + _stable_hash(branch_signature, 10))
            if evidence_status:
                suffix.append(f"evidence={evidence_status}")
            if effect_kind:
                suffix.append(f"effect={effect_kind}")
            if effect_strength:
                suffix.append(f"strength={effect_strength}")
            if effect_source:
                suffix.append(f"note={effect_source}")
            if ordering_note:
                suffix.append(f"ordering={ordering_note}")
            metadata = (" | " + " | ".join(suffix)) if suffix else ""
            lines.append(
                f"{fact_id}|{event_kind}|step={path_step}|{function_name}@{start_byte}|`{code}`{metadata}"
            )
            continue

        if mode == "compact":
            metadata = [f"step={path_step}", f"loc={function_name}@{start_byte}"]
            if parameter_index is not None:
                metadata.append(f"callee_arg={parameter_index}")
            if abstract_object:
                metadata.append(f"object={abstract_object}")
            if object_identity and object_identity != "explicit":
                metadata.append(f"identity={object_identity}")
            if guard_ids:
                metadata.append("guards=" + ",".join(guard_ids))
            if branch_signature:
                metadata.append("branch=" + _stable_hash(branch_signature, 10))
            if evidence_status:
                metadata.append(f"evidence={evidence_status}")
            if effect_strength:
                metadata.append(f"strength={effect_strength}")
            if effect_source:
                metadata.append(f"note={effect_source}")
            if ordering_note:
                metadata.append(f"ordering={ordering_note}")
            lines.append(f"{fact_id} [{event_kind}] " + " | ".join(metadata) + f" | `{code}`")
            continue

        lines.append(f"{fact_id} [{event_kind}]")
        lines.append(f"  Path step/location: {path_step}, {function_name}@{start_byte}")
        lines.append(f"  Code: `{code}`")
        if evidence_status:
            lines.append(f"  Evidence status: {evidence_status}")
        if effect_kind:
            lines.append(f"  Effect kind: {effect_kind}")
        if effect_strength:
            lines.append(f"  Evidence strength: {effect_strength}")
        if object_identity and object_identity != "explicit":
            lines.append(f"  Object identity: {object_identity} (best-effort, not proven aliasing)")
        if effect_source:
            lines.append(f"  Note: {effect_source}")
        if ordering_note:
            lines.append(f"  Ordering: {ordering_note}")
        if parameter_index is not None:
            lines.append(f"  Callee parameter index: {parameter_index}")
        if abstract_object:
            lines.append(f"  Abstract object: {abstract_object}")
        if branch_signature:
            lines.append(f"  Branch variant: {branch_signature}")
        lines.append(f"  Guard IDs (TG* = task-shared dictionary, {subpath.subpath_id}-G* = subpath-local): {guard_ids if guard_ids else 'None'}")
    return "\n".join(lines)


def _format_subpath_sinks(
    task: MultiSourcePathTask,
    subpath: SourceSubpath,
    mode: str,
    guard_lookup: Dict[str, str],
) -> str:
    lines: List[str] = []
    # The concrete operation text is printed once in the operation-relation
    # registry. Multi-subpath tasks reference it by OPx id instead of repeating
    # the text in every sink row; single-subpath tasks keep the local copy so
    # the model does not have to cross-reference for the common small case.
    operation_in_registry_only = len(task.source_subpaths) > 1
    for sink in subpath.sinks:
        sink_id = sink.get("sink_id", "S?")
        operation_id = sink.get("operation_id", "OP?")
        sink_type = sink.get("type", "Terminal")
        function_name = sink.get("function", task.target_function)
        operation = str(sink.get("operation") or "")
        guard_ids = _guard_ids(sink.get("controls"), guard_lookup)
        abstract_object = sink.get("abstract_object")
        branch_signature = _safe_list(sink.get("branch_signature"))
        start_byte = _safe_int(sink.get("start_byte"), -1)
        if mode in {"compact", "ultra"}:
            suffix: List[str] = []
            if abstract_object:
                suffix.append(f"obj={abstract_object}")
            if guard_ids:
                suffix.append("guards=" + ",".join(guard_ids))
            if branch_signature:
                suffix.append("branch=" + _stable_hash(branch_signature, 10))
            metadata = (" | " + " | ".join(suffix)) if suffix else ""
            if mode == "ultra" or operation_in_registry_only:
                lines.append(
                    f"{sink_id}/{operation_id}|{sink_type}|{function_name}@{start_byte}{metadata}"
                )
            else:
                lines.append(
                    f"{sink_id}/{operation_id}|{sink_type}|{function_name}@{start_byte}|`{operation}`{metadata}"
                )
            continue
        lines.append(f"{sink_id} / {operation_id} [{sink_type}]")
        lines.append(f"  Function/location: {function_name}@{start_byte}")
        if not operation_in_registry_only:
            lines.append(f"  Operation: `{operation}`")
        if abstract_object:
            lines.append(f"  Abstract object: {abstract_object}")
        if branch_signature:
            lines.append(f"  Branch variant: {branch_signature}")
        lines.append(f"  Guard IDs (TG* = task-shared dictionary, {subpath.subpath_id}-G* = subpath-local): {guard_ids if guard_ids else 'None'}")
    return "\n".join(lines) or "No terminal sinks."


def _partition_subpath_facts(
    subpath: SourceSubpath,
) -> Tuple[List[Dict[str, Any]], OrderedDict[Tuple[str, ...], List[Dict[str, Any]]]]:
    """Partition facts without duplication using exact sink provenance."""
    facts = _prompt_facts_for_subpath(subpath)
    selected_sink_ids = {str(sink.get("sink_id")) for sink in subpath.sinks}
    shared: List[Dict[str, Any]] = []
    local: OrderedDict[Tuple[str, ...], List[Dict[str, Any]]] = OrderedDict()
    for fact in facts:
        supported = tuple(sorted(
            sink_id for sink_id in _safe_list(fact.get("supported_sink_ids"))
            if sink_id in selected_sink_ids
        ))
        if not supported or set(supported) == selected_sink_ids:
            shared.append(fact)
        else:
            local.setdefault(supported, []).append(fact)
    return shared, local


def _subpath_render_structure_key(
    task: MultiSourcePathTask,
    subpath: SourceSubpath,
) -> Tuple[Any, ...]:
    """Exact evidence shape used only for lossless prompt rendering."""
    return (
        tuple(_subpath_call_chain(task, subpath)),
        tuple(_subpath_call_edges(task, subpath)),
        subpath.context_mode,
        subpath.source_status,
        tuple(sorted(_fact_signature(fact) for fact in _prompt_facts_for_subpath(subpath))),
        tuple(sorted(_sink_signature(sink) for sink in subpath.sinks)),
    )


def _format_compact_path_graph(task: MultiSourcePathTask) -> str:
    """Losslessly serialize many explicit paths with shared evidence dictionaries."""
    guard_ids: OrderedDict[str, str] = OrderedDict()
    fact_groups: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def guard_refs(controls: Any) -> List[str]:
        refs: List[str] = []
        for control in _safe_list(controls):
            normalized = _normalize_space(str(control))
            if not normalized:
                continue
            if normalized not in guard_ids:
                guard_ids[normalized] = f"G{len(guard_ids) + 1}"
            refs.append(guard_ids[normalized])
        return refs

    # Build registries first so every path row can reference stable objective IDs.
    for subpath in task.source_subpaths:
        for fact in _prompt_facts_for_subpath(subpath):
            marker = _fact_signature(fact)
            entry = fact_groups.setdefault(marker, {"fact": fact, "ids": []})
            entry["ids"].append(str(fact.get("fact_id") or "F?"))
            guard_refs(fact.get("controls"))
        for sink in subpath.sinks:
            guard_refs(sink.get("controls"))

    lines: List[str] = [
        "Explicit source-specific propagation paths (shared evidence is printed once):"
    ]
    for subpath in task.source_subpaths:
        fact_refs = [
            str(fact.get("fact_id") or "F?")
            for fact in _prompt_facts_for_subpath(subpath)
        ]
        terminal_refs = []
        for sink in subpath.sinks:
            refs = guard_refs(sink.get("controls"))
            guard_suffix = f":guards={refs}" if refs else ""
            terminal_refs.append(
                f"{sink.get('sink_id', 'S?')}/{sink.get('operation_id', 'OP?')}"
                f"{guard_suffix}"
            )
        lines.append(
            f"{subpath.subpath_id}/{subpath.source_id} | "
            f"source=`{subpath.source_display}` | "
            f"origin=`{_normalize_space(subpath.source_origin)}` | "
            f"status={subpath.source_status} | "
            f"path={' -> '.join(_subpath_call_chain(task, subpath))} | "
            f"edges={_subpath_call_edges(task, subpath) or ['ROOT']} | "
            f"ordered_facts={fact_refs or 'None'} | terminals={terminal_refs}"
        )
        lines.append(f"  {_source_trust_note(subpath)}")

    lines.append("Shared path-fact dictionary:")
    if not fact_groups:
        lines.append("None; these paths terminate directly at their listed operations.")
    for entry in fact_groups.values():
        fact = entry["fact"]
        metadata: List[str] = []
        if fact.get("parameter_index") is not None:
            metadata.append(f"callee_arg={fact.get('parameter_index')}")
        if fact.get("abstract_object"):
            metadata.append(f"object={fact.get('abstract_object')}")
        refs = guard_refs(fact.get("controls"))
        if refs:
            metadata.append(f"guards={refs}")
        # Observation anchors (stale-pointer / release-overlap suspects) must keep
        # their grading and explanation here: the shared dictionary is the only
        # rendering most of these facts get, and dropping the note used to hide the
        # double-free reading of an UNKNOWN_EFFECT → RELEASE pair.
        evidence_status = _meaningful_label(fact.get("evidence_status"))
        effect_strength = _meaningful_label(fact.get("effect_strength"))
        effect_source = _meaningful_label(fact.get("effect_source"))
        ordering_note = _meaningful_label(fact.get("ordering_note"))
        object_identity = _meaningful_label(fact.get("object_identity"))
        if object_identity and object_identity != "explicit":
            metadata.append(f"identity={object_identity}")
        if evidence_status:
            metadata.append(f"evidence={evidence_status}")
        if effect_strength:
            metadata.append(f"strength={effect_strength}")
        if effect_source:
            metadata.append(f"note={effect_source}")
        if ordering_note:
            metadata.append(f"ordering={ordering_note}")
        suffix = " | " + " | ".join(metadata) if metadata else ""
        lines.append(
            f"Fact IDs={_dedup_preserve_order(entry['ids'])} | "
            f"{fact.get('event_kind', 'FACT')} | "
            f"step={_safe_int(fact.get('path_step'), -1)} | "
            f"{fact.get('function', '[unknown]')}@{_safe_int(fact.get('start_byte'), -1)} | "
            f"`{fact.get('code', '')}`{suffix}"
        )

    lines.append("Shared control-condition dictionary:")
    if guard_ids:
        annotations = _task_guard_annotations(task)
        lines.extend(
            f"{guard_id}: `{control}`"
            + (f"  [{annotations[control]}]" if control in annotations else "")
            for control, guard_id in guard_ids.items()
        )
    else:
        lines.append("None")
    return "\n".join(lines)


_SOURCE_TRUST_ATTACKER_TOKENS = (
    "copy_from_user", "__copy_from_user", "get_user", "memdup_user",
    "strncpy_from_user", "recvmsg", "recvfrom", "recv(", "read(", "skb", "packet",
)


def _source_trust_note(subpath: SourceSubpath) -> str:
    """State objective origin facts for prompts.

    Deliberately neutral: attacker control is a property the model must
    establish from path evidence, not a conclusion this note may assert
    (a keyword- or caller-visibility-based trust claim would be an
    unverifiable recall-oriented prior).
    """
    origin_text = str(subpath.source_origin or "")
    lowered = origin_text.lower()
    if any(token in lowered for token in _SOURCE_TRUST_ATTACKER_TOKENS):
        return (
            "Source trust note: the origin involves a userspace/network input API; "
            "whether its content and length fields are attacker-controlled is for "
            "you to determine from the path evidence, not from this note."
        )
    if "[Entry Parameter]" in origin_text:
        return (
            "Source trust note: parameter of an entry-point function with no in-file "
            "caller; the supplied code does not establish who controls it - assess "
            "attacker influence from the listed facts and path evidence."
        )
    if not subpath.source_defining_func:
        return (
            "Source trust note: origin unresolved within the supplied code; treat the "
            "value's content and range as UNKNOWN - unknown origin is not evidence of "
            "safety."
        )
    return "Source trust note: origin shown above; assess trust from the listed facts."


def _format_source_subpaths(task: MultiSourcePathTask) -> str:
    # Equivalent source variants share one rendered spine, while every original
    # source, fact, path and sink identifier remains visible to the model.
    if len(task.source_subpaths) >= 8:
        return _format_compact_path_graph(task)
    shared_guards, local_guards, guard_lookups = _task_guard_registries(task)
    guard_annotations = _task_guard_annotations(task)
    blocks: List[str] = []
    if shared_guards:
        blocks.append(
            "Shared control-condition dictionary (guards common to multiple subpaths, "
            "printed once; TG* ids are task-level):\n"
            + "\n".join(
                f"{guard_id}: `{guard}`"
                + (f"  [{guard_annotations[guard]}]" if guard in guard_annotations else "")
                for guard, guard_id in shared_guards.items()
            )
        )
    mode = task.fact_render_mode
    for subpath in task.source_subpaths:
        guard_to_id = local_guards.get(subpath.subpath_id, OrderedDict())
        guard_lookup = guard_lookups.get(subpath.subpath_id, {})
        shared_facts, local_fact_groups = _partition_subpath_facts(subpath)
        # Empty sections are omitted entirely: printing "No facts / None" blocks
        # per subpath wastes tokens and dilutes attention on the real evidence.
        fact_blocks: List[str] = []
        shared_rendered = _format_subpath_facts(subpath, mode, guard_lookup, shared_facts)
        if shared_rendered:
            fact_blocks.extend([
                "  Shared path-spine facts (rendered once):",
                shared_rendered,
            ])
        for supported_sink_ids, local_facts in local_fact_groups.items():
            local_rendered = _format_subpath_facts(subpath, mode, guard_lookup, local_facts)
            if local_rendered:
                fact_blocks.extend([
                    f"  Sink-local fact group for {list(supported_sink_ids)}:",
                    local_rendered,
                ])
        block = [
            f"{subpath.subpath_id} / {subpath.source_id}",
            f"  Source identity: {subpath.source_display}",
            f"  Source origin: {subpath.source_origin}",
            f"  {_source_trust_note(subpath)}",
            f"  Context mode: {subpath.context_mode}",
            f"  Source status: {subpath.source_status}",
            f"  Exact call path: {' -> '.join(_subpath_call_chain(task, subpath))}",
            f"  Exact call-edge IDs: {_subpath_call_edges(task, subpath) or ['ROOT']}",
        ]
        if guard_to_id:
            block.extend([
                "  Subpath-local guard dictionary (guards shared with other subpaths are "
                "printed once in the task-level TG dictionary above):",
                _format_subpath_guards(guard_to_id, guard_annotations),
            ])
        block.extend(fact_blocks)
        block.extend([
            "  Source-specific terminal sinks:",
            _format_subpath_sinks(task, subpath, mode, guard_lookup),
        ])
        blocks.append("\n".join(block))
    return "\n\n".join(blocks) or "No source subpaths."


def _format_operation_relations(task: MultiSourcePathTask) -> str:
    entries: OrderedDict[str, Dict[str, Any]] = OrderedDict()
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            operation_id = str(sink.get("operation_id") or "OP?")
            entry = entries.setdefault(operation_id, {
                "operation": sink.get("operation", ""),
                "function": sink.get("function", task.target_function),
                "sources": [],
                "subpaths": [],
                "sinks": [],
            })
            entry["sources"].append(subpath.source_id)
            entry["subpaths"].append(subpath.subpath_id)
            entry["sinks"].append(sink.get("sink_id"))
    lines: List[str] = []
    for operation_id, entry in entries.items():
        sources = _dedup_preserve_order(entry["sources"])
        subpaths = _dedup_preserve_order(entry["subpaths"])
        sinks = _dedup_preserve_order(entry["sinks"])
        relation = "shared" if len(sources) > 1 else "source-local"
        lines.append(
            f"{operation_id} [{relation}] function={entry['function']} "
            f"sources={sources} subpaths={subpaths} sinks={sinks}"
        )
        lines.append(f"  Operation: `{entry['operation']}`")
    return "\n".join(lines) or "No terminal operation relations."


def _format_objective_operand_relations(task: MultiSourcePathTask) -> str:
    """Render API operand roles and nearby size state without vulnerability labels."""
    role_specs: Tuple[Tuple[str, Tuple[Tuple[int, str], ...]], ...] = (
        ("__copy_to_user", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("copy_to_user", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("__copy_from_user", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("copy_from_user", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("memcpy", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("memmove", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("strncpy", ((0, "destination"), (1, "source"), (2, "transfer_length"))),
        ("memset", ((0, "destination"), (1, "fill_value"), (2, "transfer_length"))),
    )
    target_code = _target_function_code(task)
    signature = target_code.split("{", 1)[0]
    size_name_hints = ("len", "size", "count", "capacity", "cap", "avail", "remain")
    pointer_parameter_names = [
        match.group(1)
        for match in re.finditer(r"\*+\s*([A-Za-z_]\w*)\b", signature)
    ]
    size_pointer_parameters = _dedup_preserve_order(
        name for name in pointer_parameter_names
        if any(hint in name.lower() for hint in size_name_hints)
    )
    operation_entries: OrderedDict[str, Dict[str, Any]] = OrderedDict()
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            operation_id = str(sink.get("operation_id") or "OP?")
            operation_entries.setdefault(operation_id, sink)

    lines: List[str] = []
    for operation_id, sink in operation_entries.items():
        operation = str(sink.get("operation") or "")
        matched_api = ""
        arguments: List[str] = []
        roles: Tuple[Tuple[int, str], ...] = ()
        for api_name, api_roles in role_specs:
            if not re.search(rf"\b{re.escape(api_name)}\s*\(", operation):
                continue
            candidate_arguments = _call_arguments(operation, api_name)
            if candidate_arguments:
                matched_api = api_name
                arguments = candidate_arguments
                roles = api_roles
                break
        if not matched_api:
            continue

        rendered_roles = [
            f"{role}=`{_normalize_space(arguments[index])}`"
            for index, role in roles
            if index < len(arguments)
        ]
        lines.append(
            f"{operation_id} `{matched_api}` operand roles: "
            + ", ".join(rendered_roles)
        )
        if matched_api in {"copy_to_user", "__copy_to_user"}:
            lines.append(
                "  API contract: the destination is user memory and the third "
                "argument is the requested transfer length."
            )
        elif matched_api in {"copy_from_user", "__copy_from_user"}:
            lines.append(
                "  API contract: the source is user memory and the third "
                "argument is the requested transfer length."
            )

        transfer_length = next((
            _normalize_space(arguments[index])
            for index, role in roles
            if role == "transfer_length" and index < len(arguments)
        ), "")
        related_parameters = [
            parameter for parameter in size_pointer_parameters
            if re.search(rf"\b{re.escape(parameter)}\b", target_code)
        ]
        if related_parameters:
            lines.append(
                "  Size-valued pointer parameters in the target function: "
                + ", ".join(f"`*{name}`" for name in related_parameters)
            )

        relation_statements: List[str] = []
        function_body = target_code.split("{", 1)[-1]
        for raw_line in function_body.splitlines():
            statement = _normalize_space(raw_line)
            if not statement or statement.startswith(("//", "/*")):
                continue
            mentions_size_parameter = any(
                re.search(rf"\b{re.escape(name)}\b", statement)
                for name in related_parameters
            )
            mentions_transfer_length = bool(
                transfer_length
                and re.search(
                    rf"(?<![A-Za-z_0-9]){re.escape(transfer_length)}(?![A-Za-z_0-9])",
                    statement,
                )
            )
            if mentions_size_parameter or (
                mentions_transfer_length and re.search(r"\b(?:if|while|for|access_ok)\b", statement)
            ):
                relation_statements.append(statement)
        if relation_statements:
            lines.append("  Related size/check statements observed in the target code:")
            lines.extend(
                f"    - `{statement}`"
                for statement in _dedup_preserve_order(relation_statements)[:8]
            )

        call_match = re.search(rf"\b{re.escape(matched_api)}\s*\(", target_code)
        code_before_operation = target_code[:call_match.start()] if call_match else target_code
        for parameter in related_parameters:
            direct_relations = []
            for raw_line in code_before_operation.splitlines():
                statement = _normalize_space(raw_line)
                if not (
                    re.search(rf"\b{re.escape(parameter)}\b", statement)
                    and transfer_length
                    and re.search(
                        rf"(?<![A-Za-z_0-9]){re.escape(transfer_length)}(?![A-Za-z_0-9])",
                        statement,
                    )
                    and re.search(r"(?:<=|>=|<|>|==|!=|\bmin(?:_t)?\s*\()", statement)
                ):
                    continue
                direct_relations.append(statement)
            if direct_relations:
                lines.append(
                    f"  Direct pre-operation relations between `{transfer_length}` and "
                    f"`*{parameter}`: "
                    + "; ".join(f"`{item}`" for item in _dedup_preserve_order(direct_relations))
                )
            else:
                lines.append(
                    f"  Direct pre-operation relation between `{transfer_length}` and "
                    f"`*{parameter}`: none observed in the target code."
                )

        if any("access_ok" in statement for statement in relation_statements):
            lines.append(
                "  API contract: `access_ok(address, size)` checks whether the supplied "
                "user-address range may be accessed; it does not compare `size` with a "
                "separate function-level transfer limit."
            )
    # Empty string: the caller omits the section entirely when no listed
    # operation has operand-role annotations.
    return "\n".join(lines)


def _format_path_scope(task: MultiSourcePathTask) -> str:
    variants = {
        (tuple(_subpath_call_chain(task, subpath)), tuple(_subpath_call_edges(task, subpath)))
        for subpath in task.source_subpaths
    }
    if len(variants) == 1:
        chain, edges = next(iter(variants))
        return (
            f"Exact call chain: {' -> '.join(chain)}\n"
            f"Exact call-edge IDs: {list(edges) or ['ROOT']}"
        )
    return (
        f"Exact path variants: {len(variants)}; each variant is listed under its SPx "
        "subpath and must be reasoned about independently."
    )


def _format_static_evidence_limitations(task: MultiSourcePathTask) -> str:
    limitations: List[str] = []
    imprecise_sources = [
        f"{subpath.source_id}/{subpath.subpath_id}"
        for subpath in task.source_subpaths
        if str(subpath.source_status or "").lower() != "precise"
    ]
    if imprecise_sources:
        limitations.append(
            "Source origin is not precisely identified for " + ", ".join(imprecise_sources)
        )

    diagnostics = task.call_graph_diagnostics or {}
    indirect_count = sum(
        _safe_int(diagnostics.get(name), 0)
        for name in ("field_dispatch_calls", "indirect_calls", "unknown_calls")
    )
    if indirect_count:
        examples = _normalize_string_list(diagnostics.get("unresolved_call_examples"))[:3]
        detail = f"; examples={examples}" if examples else ""
        limitations.append(
            f"The file-level call graph contains {indirect_count} unresolved/indirect call site(s){detail}. "
            "Treat this as a gap only when one of these calls is material to the current hypothesis."
        )
    # Empty string: the caller omits the section entirely when no limitation
    # applies to this task.
    return "\n".join(f"- {item}" for item in limitations)


def _format_lifecycle_backedge_relations(task: MultiSourcePathTask) -> str:
    """Summarize mandatory backedges that can refresh a released pointer."""
    lines = task.code_context.splitlines()
    labels: Dict[str, int] = {}
    for index, line in enumerate(lines):
        match = re.match(r"\s*([A-Za-z_]\w*)\s*:\s*$", line)
        if match:
            labels[match.group(1)] = index

    relations: List[str] = []
    for release_index, line in enumerate(lines):
        release_match = re.search(
            r"\b(?:free|kfree|xfree|g_free)\s*\(\s*([A-Za-z_]\w*)\s*\)",
            line,
        )
        if release_match is None:
            continue
        variable = release_match.group(1)
        for goto_index in range(release_index, min(len(lines), release_index + 6)):
            goto_match = re.search(
                r"\bgoto\s+([A-Za-z_]\w*)\s*;", lines[goto_index]
            )
            if goto_match is None:
                continue
            label = goto_match.group(1)
            label_index = labels.get(label)
            if label_index is None or label_index >= release_index:
                continue
            refresh_lines = [
                _normalize_space(lines[index])
                for index in range(label_index, release_index)
                if re.search(
                    rf"(?:&\s*{re.escape(variable)}\b|"
                    rf"\b{re.escape(variable)}\s*=)",
                    lines[index],
                )
            ]
            if refresh_lines:
                relations.append(
                    f"`{line.strip()}` is followed by mandatory `goto {label}`; "
                    f"the destination region can refresh `{variable}` via "
                    f"`{refresh_lines[-1]}`. A later release/use must establish "
                    "whether it refers to the pre-refresh or post-refresh object."
                )
    return "\n".join(f"- {item}" for item in _dedup_preserve_order(relations)) or "- None identified."


def _task_evidence_features(task: MultiSourcePathTask) -> Dict[str, bool]:
    """Detect which special evidence tags actually occur in this task's rendered
    facts, so prompts only explain the notation the model will really see."""
    features = {
        "unknown_effect": False,
        "effect_kind": False,
        "strength": False,
        "identity": False,
        "ordering": False,
        "lock_flag_race": False,
        "field_dangling": False,
    }
    for subpath in task.source_subpaths:
        for fact in _prompt_facts_for_subpath(subpath):
            event_kind = str(fact.get("event_kind") or "").upper()
            if event_kind == "UNKNOWN_EFFECT":
                features["unknown_effect"] = True
            elif event_kind in {
                "FLAG_CHECK_OUTSIDE_LOCK", "FLAG_WRITE_OUTSIDE_LOCK", "LIST_OP_UNDER_LOCK",
            }:
                features["lock_flag_race"] = True
            elif event_kind in {"FIELD_REFERENCE", "FIELD_NOT_CLEARED"}:
                features["field_dangling"] = True
            if _meaningful_label(fact.get("effect_kind")):
                features["effect_kind"] = True
            if _meaningful_label(fact.get("effect_strength")):
                features["strength"] = True
            identity = _meaningful_label(fact.get("object_identity"))
            if identity and identity != "explicit":
                features["identity"] = True
            if _meaningful_label(fact.get("ordering_note")):
                features["ordering"] = True
    return features


def _screening_legend(task: MultiSourcePathTask) -> str:
    """Notation legend for the screening prompt. The guard-dictionary explanation
    is always needed; lifecycle/race tag explanations are emitted only when this
    task's evidence actually carries those tags (the generic per-class invariants
    in the Target-CWE checklist below stay unconditional, so the model can still
    raise a lifecycle hypothesis from raw code when the static layer did not tag
    anything)."""
    features = _task_evidence_features(task)
    paragraphs = [
        "Guard IDs prefixed TG* refer to the task-level shared control-condition dictionary\n"
        "(printed once); SPx-G* IDs are subpath-local. A bracketed suffix on a guard entry gives\n"
        "its structured form: the effective predicate holding on the listed path (the raw\n"
        "condition is always kept), the condition kind, and best-effort operand roles\n"
        "(ARG_i(callee) = i-th argument, 0-based; RET(callee) = value returned by callee;\n"
        "|LEN = known length-parameter position). Roles are heuristic hints, not proven facts."
    ]
    if features["unknown_effect"]:
        paragraphs.append(
            "A fact tagged UNKNOWN_EFFECT marks an opaque call or macro whose effect on the listed\n"
            "object is unknown (it may release, move, or reallocate the backing storage); combined\n"
            "with an earlier ALIAS_CAPTURE and a later USE of the same object it is an observation\n"
            "anchor for a possible stale-pointer/use-after-realloc hypothesis, not proof of one.\n"
            "Combined instead with a later RELEASE of the same object on a branch-compatible path,\n"
            "it anchors a double-free/overlapping-release hypothesis: the opaque operation may\n"
            "already have released what the later operation provably releases."
        )
    if features["strength"]:
        paragraphs.append(
            "A strength= suffix on an observation fact grades that anchor "
            "(summary_proven > exact_owner > ancestor_or_macro)."
        )
    if features["effect_kind"]:
        paragraphs.append(
            "An effect=MAY_RELOCATE tag on an observation fact means a codebase defensive idiom\n"
            "(cited in the note: the code captures a buffer anchor before this operation family and\n"
            "checks for relocation afterwards) supplies file-local behavioral evidence that the\n"
            "operation may move the backing storage; it upgrades — but does not complete — the\n"
            "observation."
        )
    if features["identity"]:
        paragraphs.append(
            "An identity=<kind> tag (field_family_inferred, macro_opaque, scalar-field::<path>,\n"
            "or similar) marks a best-effort object identity built from a field family, macro\n"
            "value, or tracked field path — not proven aliasing."
        )
    if features["ordering"]:
        paragraphs.append(
            "An ordering= note on an observation fact states the analyzer's deterministic event\n"
            "order (capture/refresh positions relative to the opaque operation). It is ground\n"
            "truth for event order: never re-derive or contradict it from the raw code. A refresh\n"
            "the note places BEFORE the opaque operation does not dominate the use and never\n"
            "refutes. If you believe the note misidentifies an event, record a proof gap instead\n"
            "of silently overriding it."
        )
    if features["lock_flag_race"]:
        paragraphs.append(
            "A FLAG_CHECK_OUTSIDE_LOCK / FLAG_WRITE_OUTSIDE_LOCK / LIST_OP_UNDER_LOCK triple is a\n"
            "lock-flag race anchor: the flag guarding a list operation is checked and written outside\n"
            "the spin lock that protects the operation, so two concurrent executions on the same\n"
            "object can both pass the check and both enter the locked region. It anchors a\n"
            "race/double-entry hypothesis (e.g. CWE-362 leading to CWE-415/416); it is an observation,\n"
            "not proof — assess whether concurrent entry on the same object is feasible."
        )
    return "\n".join(paragraphs)


_BOUNDS_CWE_NUMBERS = frozenset({
    "119", "120", "121", "122", "123", "124", "125", "126", "127",
    "129", "130", "131", "787", "788", "805", "806",
})


_INTEGER_CWE_NUMBERS = frozenset({"190", "191", "192", "193", "194", "195", "196", "197"})


_LIFETIME_CWE_NUMBERS = frozenset({"415", "416", "362", "364", "366", "367", "672", "825"})


_NULL_CWE_NUMBERS = frozenset({"476"})


def _hypothesis_mechanism_families(hypotheses: Sequence[Dict[str, Any]]) -> Set[str]:
    """Map hypotheses to rubric families for the verification checklist.

    Matching is deliberately over-inclusive (CWE numbers plus free text of the
    type and root cause): any hypothesis that matches nothing recognizable
    forces ALL family blocks to be included, so a rubric block is never absent
    when it might be needed."""
    families: Set[str] = set()
    for hypothesis in hypotheses:
        cwe_numbers = set(re.findall(r"\d+", str(hypothesis.get("cwe_id") or "")))
        text = " ".join([
            str(hypothesis.get("potential_vulnerability_type") or ""),
            str(hypothesis.get("root_cause_hypothesis") or ""),
            str(hypothesis.get("suspected_broken_control") or ""),
        ]).lower()
        if cwe_numbers & _BOUNDS_CWE_NUMBERS or re.search(
            r"buffer|bound|out[- ]of[- ]bound|overread|over[- ]?read|over[- ]?write", text
        ):
            families.add("bounds")
        if cwe_numbers & _INTEGER_CWE_NUMBERS or re.search(
            r"integer|wraparound|truncation|underflow", text
        ) or ("overflow" in text and "integer" in text):
            families.add("integer")
        if "overflow" in text:
            families.add("bounds")
        if cwe_numbers & _LIFETIME_CWE_NUMBERS or re.search(
            r"use[- ]?after[- ]?free|double[- ]?free|stale|dangling|lifetime|race|realloc", text
        ):
            families.add("lifetime")
        if cwe_numbers & _NULL_CWE_NUMBERS or "null" in text:
            families.add("null")
    if not families:
        # Unrecognized mechanism: keep every rubric block (safe superset).
        families = {"bounds", "integer", "lifetime", "null"}
    return families


_VERIFICATION_BOUNDS_BLOCK = (
    "- Bounds and buffer access (CWE-119, CWE-125, and CWE-787): confirm the concrete object, its capacity or\n"
    "readable extent, the index/copy/loop length, the violated read/write side, and whether a\n"
    "same-value dominating bound blocks the operation. A guard that bounds the SOURCE extent\n"
    "(packet/body/input length) is not a bound relative to the DESTINATION capacity: never\n"
    "reject an overflow hypothesis through a capacity proof unless the destination object's\n"
    "own capacity and a length constrained by that same capacity are both established by\n"
    "supplied code. If the destination capacity is unknown, record unknown_capacity_or_extent\n"
    "as a proof gap instead of claiming a capacity-based refutation, but ONLY after deriving\n"
    "the extent from the carrier object: a pointer/length produced from a visible object\n"
    "(e.g., `p = hdr->Field(obj->Start())`, `n = obj->GetLen()`) has its capacity bounded by\n"
    "that object's own extent, established by visible or retrieved clone/allocation\n"
    "assignments and length/size accessor calls (see Carrier extent statements). Declare the\n"
    "capacity unknown only when neither the supplied code nor the retrieved carrier facts\n"
    "bound the carrier object. For capacity derived from a\n"
    "monotonically growing quantity (e.g., a doubling reallocation with no visible cap), the\n"
    "integer-family reachability rule applies: do not reject solely because the exact maximum is\n"
    "not statically established. In a cursor-advancing loop, once any iteration establishes\n"
    "`cursor + K <= bound` — whether the check sits before the advance (`cursor + K > bound\n"
    "bails out`) or right after it (`cursor` advanced, then `cursor + K > bound` bails out) —\n"
    "the condition-time read of K bytes at `cursor` in the FOLLOWING iteration is guarded,\n"
    "and the first iteration is guarded by the loop-entry checks: evaluate 'read before\n"
    "check' claims against this loop-carried invariant, not against textual order within a\n"
    "single iteration. A condition-position read is 'unguarded' only when some path reaching\n"
    "it lacks a guard for the read extent: enumerate the paths (loop entry via the entry\n"
    "checks, back-edge via the previous iteration's body check) and name the guard on each\n"
    "before claiming an unguarded read."
)


_VERIFICATION_INTEGER_BLOCK = (
    "- Integer safety (CWE-190 and CWE-191): confirm operand types/ranges, the arithmetic or conversion,\n"
    "check-domain consistency, and a concrete security-relevant consequence. Wraparound alone\n"
    "is insufficient when allocation and use remain governed by the same safe expression.\n"
    "Reachability of the overflow threshold follows a strict rule: when the overflowing quantity\n"
    "grows monotonically through code-visible operations (repeated doubling, per-request\n"
    "increments) and NO upper bound on it appears anywhere in the supplied code, the threshold\n"
    "is reachable in principle — a missing maximum value is an attacker-side magnitude question,\n"
    "not a blocking gap. Confirm at Medium or Low confidence with the assumption recorded in\n"
    "proof_gaps; reject on reachability grounds only when supplied code contains a concrete\n"
    "bound that keeps the quantity below the threshold."
)


_VERIFICATION_NULL_BLOCK = (
    "- Null dereference (CWE-476): confirm a concrete nullable origin/state, NULL-compatible path,\n"
    "exact dereference, and no sufficient dominating check. Missing checks or unknown producer\n"
    "behavior alone do not prove nullability. For a pointer parameter or caller-supplied\n"
    "object, \"the caller may pass NULL\" alone is not a concrete nullable origin: reject unless\n"
    "the analyzed code itself establishes nullability. A concrete producer call feeding the\n"
    "dereference does qualify as a nullable-origin candidate: when you can name the concrete\n"
    "condition under which that producer returns NULL (allocation failure, lookup miss,\n"
    "unregistered id), treat it as an assumed contract, confirm at Medium or Low confidence\n"
    "only, and record the assumption in proof_gaps. A field-access chain rooted at a global\n"
    "or macro (e.g., `current->nsproxy`), rather than at a caller-supplied parameter,\n"
    "qualifies under the same rules when you can name the concrete NULL condition.\n"
    "Two hard limits: a field read on a caller-supplied parameter or on an object derived\n"
    "from one (e.g., `file->private_data`, `tun->sk`) never qualifies — UNLESS the\n"
    "supplied code itself NULL-checks the same field elsewhere (e.g., a sibling function\n"
    "guards `!obj->field` or `obj->field == NULL`), or the field's visible in-file\n"
    "assignment comes from a fallible producer (allocation or lookup call) without an\n"
    "intervening check: both are concrete codebase evidence that the field can be NULL,\n"
    "so nullability is then ESTABLISHED\n"
    "by codebase convention and the field qualifies at Medium or Low confidence; record\n"
    "only the unseen producer condition (e.g., where the field is cleared) as a proof\n"
    "gap, never the nullability itself. Separately, if your proof_gaps state that the\n"
    "origin's nullability is unknown or unproven, no concrete nullable origin exists —\n"
    "confirming then is a contradiction, so the verdict must be Not Vulnerable.\n"
    "When the null scenario rests on a\n"
    "hypothetical caller action, set boundary_status to Unknown (never Established or\n"
    "Plausible) — an Established boundary requires attacker control shown in the supplied\n"
    "code, and mislabeling it does not rescue the hypothesis. Strong evidence: a reachable\n"
    "`return NULL` in the producer, an explicit NULL assignment on the current path, or a\n"
    "static note that an observed check does not exclude NULL. A NULL check on the same\n"
    "pointer elsewhere in scope is only supporting evidence that the codebase treats the\n"
    "pointer as nullable; confirm it is consistent with the current path before accepting.\n"
    "When the cited evidence is this insufficiency note, the defect under review is the\n"
    "insufficient guard itself (error pointers checked, NULL never excluded before the\n"
    "dereference); producer-body invisibility is then not a blocker and must not be counted\n"
    "as counterevidence, though the root-cause statement must still explain why the\n"
    "producer's contract can yield NULL here."
)


_VERIFICATION_LIFETIME_BASE = (
    "- Object lifetime (CWE-415 and CWE-416): confirm same-object identity and an executable ordered\n"
    "release-release or invalidation-stale-use sequence. Reject combinations across different\n"
    "objects, mutually exclusive branches, intervening refresh/reassignment, or ownership\n"
    "transfer. Two similarly named pointers or release calls are not sufficient. For a\n"
    "stale-pointer/use-after-realloc hypothesis anchored by an ALIAS_CAPTURE → UNKNOWN_EFFECT →\n"
    "USE observation chain, the missing definition of the opaque callee or macro is NOT\n"
    "counterevidence: refutation requires positive evidence — a refresh or re-derivation of the\n"
    "same pointer after the opaque operation, proof that the opaque operation cannot release or\n"
    "move the object, or branch exclusion. Before claiming a refresh/recomputation blocker,\n"
    "check the deterministic event order (step/byte positions and any ordering= note on the\n"
    "observation facts): only a refresh strictly between the UNKNOWN_EFFECT operation and the\n"
    "use refutes the chain; a refresh that precedes the UNKNOWN_EFFECT operation leaves the\n"
    "saved pointer stale at the use and does not refute. The same program-order discipline\n"
    "applies to any state guard cited as a blocker: state explicitly whether the guard is\n"
    "evaluated before the cited operation. A state check that is evaluated only AFTER the\n"
    "cited call (e.g., the risky helper is invoked unconditionally at the top of the\n"
    "function and the registration/liveness check follows it) cannot block that call and\n"
    "is not counterevidence for it.\n"
    "\n"
    "  Effect-kind adjudication standard. Every state-changing link carries one of:\n"
    "  PROVEN_NO_EFFECT (visible body contains no release/reallocation and every call\n"
    "  resolves to an effect-free in-file summary), MAY_RELOCATE / MUST_RELOCATE,\n"
    "  MAY_RELEASE / MUST_RELEASE (derivable from a visible body, a macro expansion, a\n"
    "  transitive callee summary, or an unambiguous standard/platform contract such as\n"
    "  C allocator semantics), or UNKNOWN (an external callee or undefined macro whose\n"
    "  body is not supplied). Confirm the hypothesis when object identity, event order,\n"
    "  and branch compatibility hold and every essential state-changing link is at\n"
    "  least MAY_* — a vulnerability requires only one feasible execution. An UNKNOWN\n"
    "  link neither confirms nor refutes: record an unresolved_effect proof gap naming\n"
    "  the unresolved callee/macro, and if it is the essential link, do not confirm.\n"
    "  Never invent callee or macro semantics in either direction: do not claim an\n"
    "  opaque operation releases or moves the object, and do not claim it \"can only\"\n"
    "  misbehave under conditions that would neutralize the chain. Function names or\n"
    "  similarity alone never establish an effect. The one sanctioned exception is an\n"
    "  unambiguous platform contract — well-known kernel/libc/library semantics that\n"
    "  a systems programmer would treat as documented behavior. On such a contract you\n"
    "  may upgrade an UNKNOWN link to MAY_RELEASE (never MUST_RELEASE): reference-\n"
    "  consuming destructors (kfree_skb, put_page, blk_put_request, *_put — the object\n"
    "  is released when the dropped reference is the last one), lifecycle-terminating\n"
    "  completions (blk_end_request* completes and releases the request), and\n"
    "  completion callbacks (invoking ->ki_complete/->complete transfers ownership of\n"
    "  the completed object, so the caller must not touch it afterwards).\n"
    "  Symmetrically, an unambiguous read-only contract supports PROVEN_NO_EFFECT:\n"
    "  pure query/comparison/lookup helpers (strlen, strcmp, capability or match\n"
    "  checks) do not release their arguments. Obscure or project-specific functions\n"
    "  stay UNKNOWN — when you rely on a contract, name it explicitly in the\n"
    "  reasoning. The contract resolves only the effect link; object identity, event\n"
    "  order, branch compatibility, and refresh/refutation are adjudicated normally.\n"
    "  A lock-based defense must name the lock that serializes the RELEASE path, not\n"
    "  just the use path: a lock held at the use site only excludes concurrent\n"
    "  release; it cannot exclude a release or unregistration that already completed\n"
    "  before entry (e.g., the hypothesis scenario is an already-unregistered object\n"
    "  whose state flags are visible in the code). If you cannot establish that the\n"
    "  release path requires the same lock, the lock defense is a proof gap, not\n"
    "  counterevidence.\n"
    "  A second exception with concrete\n"
    "  provenance: when an effect note cites a codebase defensive idiom (the code\n"
    "  captures a buffer anchor before the operation and checks for relocation\n"
    "  afterwards at a listed site), the link is upgraded to MAY_RELOCATE on\n"
    "  file-local behavioral evidence — treat it as MAY_* evidence, not as a name\n"
    "  guess, and evaluate the rest of the chain normally. A weaker variant cites the\n"
    "  idiom without covering this operation's window (defensive-pattern\n"
    "  inconsistency: the storage is proven relocation-prone and this chain holds a\n"
    "  raw pointer across the operation undefended); it still counts as MAY_*, but\n"
    "  lower your confidence and scrutinize object identity and event order strictly.\n"
    "  Container/framework-published objects: when deterministic lifetime-link\n"
    "  evidence shows the released object was stored into a container or registered\n"
    "  with a framework, and no unregister/removal from that same container dominates\n"
    "  the release, a later reacquire from the container (or a framework-held\n"
    "  reference) is a feasible stale use in a FUTURE invocation — confirm when the\n"
    "  published object identity holds. The blocker for a container link is a\n"
    "  dominating unregister/removal shown in the evidence; the blocker for a\n"
    "  framework registration is a release-callback/refcounted-release contract\n"
    "  (e.g., a `.release` assignment plus put_device-style frees) — a deregistration\n"
    "  call (device_del) alone does not release framework-held references. For a\n"
    "  cross-entry-point same-type link, the blocker is lock serialization of BOTH\n"
    "  the release and the use site by the same lock as annotated, or proof the two\n"
    "  sites cannot refer to one allocation."
)


_VERIFICATION_LIFETIME_RACE = (
    "  For a lock-flag race observation (FLAG_CHECK_OUTSIDE_LOCK /\n"
    "  FLAG_WRITE_OUTSIDE_LOCK / LIST_OP_UNDER_LOCK): the vulnerability requires one\n"
    "  feasible INTERLEAVING, not one sequential execution — two concurrent entries on\n"
    "  the same object both observing the pre-write flag value suffices. Confirm when\n"
    "  the flag check/write are indeed outside the lock guarding the list operation\n"
    "  and concurrent entry on the same object is feasible (the path is reachable from\n"
    "  concurrent syscalls/callbacks on a shared object). Reject when the flag\n"
    "  accesses are serialized another way: a caller-held lock covering every call\n"
    "  site visible in the supplied code, an atomic flag type, or a proof the object\n"
    "  cannot be shared across threads."
)


_VERIFICATION_LIFETIME_REFUTATION = (
    "  Refutation of an observation chain\n"
    "  is valid only via PROVEN_NO_EFFECT, a dominating refresh/reassignment strictly\n"
    "  between the opaque operation and the use, a field clear or object replacement,\n"
    "  or branch exclusion. A state update counts as refutation only when it dominates\n"
    "  the use, targets the same entity, and establishes an independent safe value: a\n"
    "  bulk copy over the host structure does not by itself clear or refresh a dangling\n"
    "  field inside it (the copied bytes may carry the same released pointer), and a\n"
    "  conditional reassignment of the field dominates only the paths where its\n"
    "  condition holds. Retrieved lifetime evidence (VEC) lists candidate\n"
    "  refresh/clear/replacement write sites with byte positions relative to this\n"
    "  operation, or states that a function-wide scan found NO write to the tracked\n"
    "  entity; use these concrete sites — do not assume or imagine a refresh. When\n"
    "  an analyzer ordering note is present it decides the dominance question:\n"
    "  a refresh the note places before the opaque operation does not refute, and\n"
    "  you must not assert a dominating refresh that contradicts the note."
)


_VERIFICATION_LIFETIME_FIELD_DANGLING = (
    "  For a field-dangling observation (FIELD_REFERENCE → RELEASE → FIELD_NOT_CLEARED),\n"
    "  the later use is legitimately a FUTURE invocation: the field is read at entry of\n"
    "  every call of the same function or of another accessor of the same host object.\n"
    "  When the host object outlives one call (a parameter/parent structure not released\n"
    "  here), the field is never cleared after the release, and the function can be\n"
    "  invoked again (concrete in-file call sites, or it is an entry point of the\n"
    "  visible code unit — no in-file caller — so code outside the supplied unit can\n"
    "  invoke it, including framework callbacks), one subsequent call is enough — a\n"
    "  vulnerability requires only one feasible execution. Do not reject such an\n"
    "  observation solely because the supplied code shows no dereference after the\n"
    "  release within a single invocation."
)


_VERIFICATION_LIFETIME_STRENGTH = (
    "  Weigh the marked evidence strength: strength=summary_proven means a\n"
    "  helper summary proves the release; strength=exact_owner means the opaque operation received\n"
    "  the object's own handle; strength=ancestor_or_macro (or a bare macro statement) is weak.\n"
    "  The strength grade informs your confidence, but it never substitutes for the\n"
    "  effect-kind standard above: a weak (UNKNOWN) essential link stays a proof gap\n"
    "  no matter how well-anchored the rest of the chain is."
)


_VERIFICATION_LIFETIME_IDENTITY = (
    "  Abstract object\n"
    "  identities derived from field families (obj->cur/base/end/...), key-equivalent matches\n"
    "  (identity=key_equivalent_alias), or all-caps macro values are\n"
    "  best-effort identities, not proven aliasing; do not treat a shared identity tag as a proven\n"
    "  same-object fact."
)


def _verification_lifetime_block(features: Dict[str, bool], race_relevant: bool) -> str:
    """Lifetime rubric with tag-specific clarifications only when the task's
    evidence actually carries those tags."""
    parts = [_VERIFICATION_LIFETIME_BASE]
    if race_relevant:
        parts.append(_VERIFICATION_LIFETIME_RACE)
    parts.append(_VERIFICATION_LIFETIME_REFUTATION)
    if features["field_dangling"]:
        parts.append(_VERIFICATION_LIFETIME_FIELD_DANGLING)
    grading: List[str] = []
    if features["strength"]:
        grading.append(_VERIFICATION_LIFETIME_STRENGTH)
    if features["identity"]:
        grading.append(_VERIFICATION_LIFETIME_IDENTITY)
    if grading:
        parts.append("\n".join(grading))
    return "\n".join(parts)


def _screening_prompt(task: MultiSourcePathTask) -> str:
    is_block_fallback = any(
        sp.context_mode == "block_fallback" for sp in task.source_subpaths
    )
    block_fallback_note = (
        """
Block-review triage rule (this task is a block review of high-risk sites that precise
path analysis did not cover): the listed sites are a priority-ranked, possibly truncated
selection. First triage them - a hypothesis is warranted only for a site that could
plausibly combine untrusted influence, a missing control, and a dangerous operation.
Emit at most 3 hypotheses for the strongest sites, and none when no site is credible.
Do not emit one hypothesis per site.
"""
        if is_block_fallback else ""
    )
    legend = _screening_legend(task)
    if SINGLE_STAGE:
        # Single-stage ablation: the screener IS the final detector. Frame the
        # task as balanced final verdicts, not high-recall hypothesis generation.
        role_line = (
            "You are a single-stage C/C++ vulnerability detector. Your hypotheses are the\n"
            "final verdicts: report only vulnerabilities the supplied code evidence\n"
            "substantiates, and weigh precision as heavily as recall."
        )
        decision_1 = (
            "1. This is the final detection stage, not a high-recall screen: report a hypothesis\n"
            "only when a concrete listed operation and path evidence substantiate its broken\n"
            "invariant."
        )
        decision_4 = (
            "4. Decide as a final detector: an unresolved essential causal link weakens the\n"
            "case - report only when the remaining evidence still substantiates the violation."
        )
    else:
        role_line = (
            "You are the high-recall screening stage of a C/C++ vulnerability analysis system."
        )
        decision_1 = (
            "1. Screening is high recall, but every hypothesis still requires a concrete listed operation\n"
            "and path evidence for its broken invariant."
        )
        decision_4 = (
            "4. Lack of a dynamic proof-of-concept is not a reason to omit an otherwise code-supported\n"
            "hypothesis, but an unresolved essential causal link must be stated as a precondition."
        )
    operand_relations = _format_objective_operand_relations(task)
    operand_section = (
        f"Objective operation-operand relations:\n{operand_relations}\n\n"
        if operand_relations else ""
    )
    macro_section = (
        f"Relevant macro definitions:\n{task.macro_context}\n\n"
        if task.macro_context else ""
    )
    limitations = _format_static_evidence_limitations(task)
    limitations_section = (
        f"Static evidence limitations:\n{limitations}\n\n" if limitations else ""
    )
    lifetime_link_section = (
        "Cross-function object-lifetime links (deterministic file-wide scan; these are\n"
        "extracted code facts, not confirmed relations - verify object identity, event\n"
        "order, and branch compatibility yourself):\n"
        f"{task.lifetime_link_context}\n\n"
        if task.lifetime_link_context else ""
    )
    return f"""
{role_line}
Analyze one terminal function and its exact source-specific path variants. Each SPx is
an independently built TPT path; alias spellings of the same source origin are already
merged into one SPx. Different sources appear in the same task only under
the configured batching policy: {task.batching_mode}.
{legend}

Generate one canonical, code-supported root-cause hypothesis for each distinct invariant
violation at the explicitly listed Sink IDs. Start from the operation and its path evidence,
then determine which invariant is implicated: capacity/range, arithmetic, initialization or
state, nullability, lifetime, or another concrete security condition. Do not prioritize one
class merely because the code contains pointers or dereferences. A hypothesis may cite
several sources only when a concrete listed operation or explicit data relation connects
them. Consolidate path variants and multiple sinks that express the same cause.
For each hypothesis, state the broken control, necessary preconditions, and security-boundary
assumption. Use Unknown when the context does not establish a boundary.
{block_fallback_note}
Mandatory source-isolation rules:
1. Every fact, guard, object, and sink belongs to its explicit SPx/SRCx subpath;
TG* guards are shared evidence explicitly listed for each subpath they constrain.
2. Do not apply a guard from one subpath to another unless the code proves that guard
dominates the same concrete operation for both sources (a TG* guard listed for both
subpaths already satisfies this for its listed text).
3. Do not combine an INVALIDATE/RELEASE from one object with a USE from another object.
4. Cross-source reasoning is allowed for concrete relations such as destination + write
length, source buffer + read length, index + referenced buffer, count + element size,
or capacity + write length.
5. OPx identifies one concrete terminal operation reached by one or more sources. Shared
OPx is evidence of a relation, not evidence that a vulnerability necessarily exists.
6. Do not combine facts from mutually exclusive call sites or branches.

Target-CWE evidence checklist (the order does not imply priority):
1. Bounds and buffer access (CWE-119, CWE-125, and CWE-787): relate the accessed object to its
allocation/capacity or readable extent, the index/copy/loop length, and every dominating
bound. Distinguish destination writes from source reads and identify the violated side.
2. Integer safety (CWE-190 and CWE-191): establish operand types and feasible ranges, the exact
arithmetic/conversion, the relevant checks in the same numeric domain, and a concrete
consequence such as an incorrect allocation, access bound, control decision, or state.
3. Object lifetime (CWE-415 and CWE-416): establish one concrete object/allocation generation and
an ordered, branch-compatible release-release or invalidation-stale-use sequence. Account
for aliases, reassignment, ownership transfer, and intervening object replacement. When an
ALIAS_CAPTURE → UNKNOWN_EFFECT → USE observation chain is listed for one object, consider
a use-after-realloc/stale-pointer hypothesis: name the saved pointer, the opaque operation
whose semantics could release or move the object, and the un-refreshed use. When an
UNKNOWN_EFFECT → RELEASE pair is listed for one object on a branch-compatible path,
consider a double-free/overlapping-release hypothesis: name the opaque operation that may
already have released the object and the later provable release of the same object. For
every RELEASE of an object, also ask whether that object remains reachable elsewhere: when
the supplied evidence (including cross-function lifetime-link evidence when present) shows
the released object was published into a container (hash/list/drvdata) or registered with
a framework and no unregister or removal dominates the release, consider a
free-without-unregister hypothesis naming the container and the reacquire site; when it
shows a same-typed object dereferenced in another entry point, consider a cross-entry-point
release/reuse hypothesis and weigh any lock annotations.
4. Null dereference (CWE-476): establish a concrete nullable origin/state, a NULL-compatible
path, the exact dereference, and the absence or insufficiency of a dominating check. The
absence of a nearby NULL check or pointer syntax alone does not establish nullability.
For a pointer parameter or a caller-supplied object, "the caller may pass NULL" alone is
not a nullable origin. Strong in-scope evidence: a reachable `return NULL` in the
producer, an explicit NULL assignment on the current path, a nullable API contract, or an
explicit static note that an observed check does not exclude NULL. A concrete producer
call whose result flows to the dereference is a nullable-origin candidate even when the
producer body is not in scope: if you can name the concrete condition under which that
producer returns NULL (e.g., allocation failure, lookup miss, unregistered id), treat its
nullability as an assumed contract, confirm at Medium or Low confidence only, and record
the assumption in proof_gaps. Do not reject such a hypothesis solely because the producer
body is not visible; reject it when the producer cannot plausibly return NULL or when a
dominating check exists. A NULL check on the same pointer elsewhere in the analyzed code
is only supporting evidence that the codebase treats the pointer as nullable; weigh it
against the current path. A field-access chain rooted at a global or macro (not at a
caller-supplied parameter), such as `current->nsproxy->net_ns`, is likewise a
nullable-origin candidate when you can name the concrete condition under which the
field is NULL (e.g., kernel threads have no nsproxy); the same assumed-contract rules
apply (Medium or Low confidence only, assumption recorded in proof_gaps). When the
insufficiency note is present, the hypothesized defect is the insufficient guard itself
(the code checks for error pointers but never excludes NULL before dereferencing); do
not discard the hypothesis merely because the producer body is not visible in the
supplied code.

Cross-cutting state evidence:
- Track initialization, error handling, field/counter updates, and relevant concurrent state
changes when they determine one of the invariants above. Do not infer a vulnerability class
until the supplied path shows the resulting unsafe operation or security-relevant failure.

Decision rules:
{decision_1}
2. Do not invent source control, aliasing, capacities, nullable states, event order, guards,
or cross-path relations.
3. Treat extracted controls as conditions to verify against code, not automatic proof of
safety or vulnerability. A check matters only if it dominates the operation and constrains
the same value, object, state, or numeric domain.
{decision_4}
5. Return an empty hypotheses list only when no credible hypothesis is supported.
6. Every hypothesis must reference valid Source IDs, Subpath IDs, Fact IDs, and Sink IDs.
The shared code context supports interpretation of listed evidence; it may complete the
semantics of a directly connected call or object-state transition, but do not mine or
report an unrelated operation.
7. Use the most specific vulnerability type and CWE supported by the evidence; do not force
a target category when its defining invariant is absent.

{_format_path_scope(task)}
Target function: {task.target_function}
Batching mode: {task.batching_mode}
Number of independent source subpaths: {len(task.source_subpaths)}

Concrete operation relations:
{_format_operation_relations(task)}

{operand_section}Independent source-specific TPT subpaths:
{_format_source_subpaths(task)}

{macro_section}{limitations_section}{lifetime_link_section}Shared relevant code context:
{task.code_context}

Output contract:
{_json_schema_example_screening()}
""".strip()


def _format_hypotheses(
    task: MultiSourcePathTask,
    hypotheses: Sequence[Dict[str, Any]],
) -> str:
    lines: List[str] = []
    for hypothesis in hypotheses:
        lines.append(f"{hypothesis['hypothesis_id']}")
        lines.append(f"  Potential type: {hypothesis.get('potential_vulnerability_type', 'N/A')}")
        lines.append(f"  CWE: {hypothesis.get('cwe_id', 'N/A')}")
        lines.append(f"  Root-cause hypothesis: {hypothesis.get('root_cause_hypothesis', '')}")
        lines.append(f"  Suspected broken control: {hypothesis.get('suspected_broken_control', '')}")
        lines.append(f"  Required preconditions: {hypothesis.get('required_preconditions', [])}")
        lines.append(f"  Boundary assumption: {hypothesis.get('security_boundary_assumption', 'Unknown')}")
        lines.append(f"  Relevant sources: {hypothesis.get('relevant_source_ids', [])}")
        lines.append(f"  Relevant subpaths: {hypothesis.get('relevant_subpath_ids', [])}")
        lines.append(f"  Relevant facts: {hypothesis.get('relevant_fact_ids', [])}")
        lines.append(f"  Relevant sinks: {hypothesis.get('relevant_sink_ids', [])}")
    return "\n".join(lines)


def _verification_prompt(task: MultiSourcePathTask, hypotheses: Sequence[Dict[str, Any]]) -> str:
    required_ids = [item["hypothesis_id"] for item in hypotheses]
    families = _hypothesis_mechanism_families(hypotheses)
    features = _task_evidence_features(task)
    race_relevant = features["lock_flag_race"] or any(
        "362" in re.findall(r"\d+", str(item.get("cwe_id") or ""))
        or "race" in str(item.get("potential_vulnerability_type") or "").lower()
        for item in hypotheses
    )
    bounds_block = (_VERIFICATION_BOUNDS_BLOCK + "\n") if "bounds" in families else ""
    integer_block = (_VERIFICATION_INTEGER_BLOCK + "\n") if "integer" in families else ""
    lifetime_block = (
        _verification_lifetime_block(features, race_relevant) + "\n"
        if "lifetime" in families else ""
    )
    null_block = (_VERIFICATION_NULL_BLOCK + "\n") if "null" in families else ""
    operand_relations = _format_objective_operand_relations(task)
    operand_section = (
        f"Objective operation-operand relations:\n{operand_relations}\n\n"
        if operand_relations else ""
    )
    vec_evidence = _format_vec_counterevidence(task, hypotheses)
    vec_section = (
        "Hypothesis-relevant retrieved evidence (deterministic static retrieval, selected by\n"
        "each hypothesis's mechanism family and cited sinks; function-scope, branch scope\n"
        "marked UNKNOWN where undetermined - these are candidate facts, not confirmed\n"
        "counter-evidence: verify dominance, path compatibility, and entity alignment\n"
        "yourself before treating any item as a blocker):\n"
        f"{vec_evidence}\n\n"
        if vec_evidence else ""
    )
    lifetime_link_section = (
        "Cross-function object-lifetime links (deterministic file-wide scan; candidate\n"
        "facts, not confirmed relations - verify object identity, event order, and\n"
        "branch compatibility yourself):\n"
        f"{task.lifetime_link_context}\n\n"
        if task.lifetime_link_context and "lifetime" in families else ""
    )
    macro_section = (
        f"Relevant macro definitions:\n{task.macro_context}\n\n"
        if task.macro_context else ""
    )
    limitations = _format_static_evidence_limitations(task)
    limitations_section = (
        f"Static evidence limitations:\n{limitations}\n\n" if limitations else ""
    )
    if REVIEW_MODE == "plain":
        # Ablation A4 (VUL_REVIEW_MODE=plain): generic second-pass review
        # without the adversarial attacker/defender framework and without the
        # support/counterevidence/proof-gap evidence discipline.
        review_framework = """You are the second-pass C/C++ vulnerability reviewer. Review every supplied
root-cause hypothesis independently, but return all verdicts in ONE structured response.

For each hypothesis, re-examine the cited operation(s) and path evidence against the
supplied code context and decide whether the claimed invariant violation holds. Confirm
when the cited evidence supports the specific violated invariant; reject when it does
not. Do not replace a weak hypothesis with an unrelated vulnerability from supporting
code."""
    else:
        review_framework = """You are the second-pass adversarial C/C++ vulnerability verifier. Review every supplied
root-cause hypothesis independently, but return all verdicts in ONE structured response.

For each hypothesis:
A. Attacker case: construct the strongest code-supported triggering input/state and trace
every cited source through its own SPx subpath to the cited operation(s).
B. Defender case: identify the strongest real code-level blocker: dominating bounds
checks, mutually exclusive branches, pointer refresh/recomputation, ownership transfer,
safe narrowing, loop invariants, destination capacity proof, or unreachable conditions.
C. Resolution: confirm only when the cited evidence supports the specific violated
invariant and every necessary causal link, and the strongest defense does not block it.
Reject when a decisive blocker exists, events cannot co-occur, source/object identity is
wrong, or an essential causal link is absent. Do not replace a weak hypothesis with an
unrelated vulnerability from supporting code.
D. Evidence status: separate supporting evidence, concrete counterevidence, and unresolved
proof gaps. A proof gap is a fact necessary to confirm or reject the hypothesis that is
absent from the supplied context; adverse evidence is counterevidence, not a proof gap.
Gap discipline is symmetric in both directions: a gap about attacker-side magnitude (how
large a value can grow) does not block confirmation, but a gap about WHETHER the violation
condition can hold at all blocks confirmation — record it as a proof gap and reject. The
distinction is mechanical: a capacity/extent gap blocks confirmation only when the
violation requires the capacity to fall BELOW a fixed, attacker-independent requirement
(a configuration or allocation that must cover a constant size). When the violation
instead requires an attacker-influenced length, index, or count to EXCEED the capacity —
or the offending value is shown to wrap near its type's maximum, which exceeds any
physically possible allocation — the gap is attacker-side magnitude and never blocks.
A mere possibility that an unseen DEFENSE exists (inside an opaque callee or caller) is
not a violation-condition gap; treat it under the imagined-validation rules above instead.
E. Hypothesis repair: the screener's type or wording is provisional. If the cited operation
and path support a different, more precise vulnerability mechanism, correct the type and
root cause instead of rejecting an otherwise credible finding."""
    load_bearing_block = (
        """Load-bearing test, ONLY for gaps about the range or magnitude of a value
(operand size, index, count, length, threshold reachability): mentally resolve
the gap in the weakest attacker-favorable way consistent with the supplied code,
then re-check whether the violation still holds. If it does, the gap is not
load-bearing and cannot justify rejection. When an arithmetic expression has
several operands, judge each operand's range against its own origin: an
attacker-influenced operand (input/payload length, count, index) may take its
extreme value, and uncertainty about an unrelated caller-contract operand (e.g.,
an output buffer's advertised size) cannot block a violation that the
attacker-side operand alone suffices to trigger.
This test NEVER applies to gaps about the existence, effectiveness, or
compilation of a defense, nor to gaps about object capacity, destination extent,
alias identity, or callee/helper semantics — those gaps continue to block
exactly as stated above.
"""
        if LOAD_BEARING_RULE
        else ""
    )
    return f"""
{review_framework}

Mandatory isolation rules:
1. Keep every SPx source subpath independent unless a cited concrete operation or explicit
data relation connects the sources.
2. A guard from SP1 cannot prove SP2 safe unless it is a shared dominating guard for the
same operation.
3. Never join lifecycle events across different abstract objects or mutually exclusive
branches/call sites.
4. Shared OPx means the same concrete operation is reached by multiple sources; each
source's role, range, and constraints must still be proven. Repeated Sink IDs mapped to
one OPx are one execution site and cannot serve as two distinct release events.
5. Return exactly one finding for every required hypothesis_id, in the required order.

Target-CWE verification checklist (only mechanism families relevant to the
supplied hypotheses are included; apply every block shown):
{bounds_block}{integer_block}
{lifetime_block}
{null_block}

Cross-cutting verification rules:
- Examine initialization, error propagation, field/counter updates, and concurrency only when
they causally establish or block the hypothesized invariant violation. A synchronization
claim must cover the relevant check, state transition, and operation on the same object.
- Do not confirm merely because a dangerous API, pointer access, arithmetic expression, free,
or missing check exists. Conversely, do not reject solely because no dynamic PoC is supplied.
- A blocker must be established by supplied code or an unambiguous standard/platform contract.
Do not invent caller invariants, protocol limits, object layouts, helper semantics,
reallocation-awareness checks, pointer-refresh guarantees, cleanup on error paths, or input
validity. Record a material missing fact as a proof gap rather than as counterevidence.
- Do not confirm while a proof gap necessary to establish the violation remains
unresolved: a missing causal link cannot support confirmation. Gaps about
attacker-side reachability or input magnitude never block (attacker control is a
threat-model assumption); this includes the maximum value of a monotonically
growing quantity (doubling capacity, per-event counters) when no upper bound is
visible anywhere in the supplied code. Gaps about defensive validation
elsewhere or helper semantics block until resolved (subject to the
imagined-validation clauses below). Capacity/extent gaps follow the symmetric
discipline in rule D: they block ONLY when the violation requires the capacity
to fall below a fixed, attacker-independent requirement (a configuration or
allocation that must cover a constant size); when the violation requires an
attacker-influenced length, index, or count to EXCEED the capacity, or the
offending value is shown to wrap near its type's maximum (exceeding any
physically possible allocation), the gap is attacker-side magnitude and does
not block. An imagined
caller-side validation cannot block when the retrieved conditions for the cited
entities were shown and none of them performs that validation — absence after a
concrete scan is evidence of absence, not a gap. The same holds for an imagined
CALLEE-side validation: when an opaque callee consumes a pointer and length as
its operation extent (decrypt/copy/read/write N bytes), bounding that length is
the caller's responsibility, so the missing callee body is a
missing_function_body proof gap, not a blocker. Helper semantics block only
when the helper's behavior IS the violation mechanism itself (e.g., whether a
helper reserves a terminator byte), not when the helper could merely contain
an unseen defense.
{load_bearing_block}Self-consistency requirement: if you question whether a
VISIBLE defense is present, compiled in, or actually executed (e.g., whether an
assertion macro is a runtime check, or claiming it "may be compiled out" or
"might be disabled") — whether the doubt appears in proof_gaps or as a dismissal
reason in defenses_considered — then the verdict for that hypothesis must be Not
Vulnerable: confirming while doubting the defense's existence is a
contradiction. Judging a defense's adequacy for the hypothesized violation (it
does not dominate the operation, constrains a different value, or is
path-incompatible) is legitimate dismissal and is NOT covered by this rule. One
narrow exception for the null family: when the hypothesis cites a concrete
producer — a call, or a field-access chain rooted at a global or macro rather
than at a caller-supplied parameter (e.g., `current->nsproxy`) — whose result
is dereferenced without a dominating NULL check, and the only unresolved gap is
whether that producer can yield NULL, the producer is a concrete
nullable-origin candidate. You may confirm at Medium or Low confidence (never
High), recording the producer's assumed NULL condition explicitly in
proof_gaps and in vulnerability_root_cause. A bare parameter or caller-supplied
pointer never qualifies for this exception, and neither does a field read on such
a parameter or on an object derived from one (e.g., `file->private_data`). If a
proof gap states that the origin's nullability is unknown or unproven, no
concrete nullable origin exists: confirming would contradict your own recorded
gap, so the verdict must be Not Vulnerable.
- A check is relevant only if it dominates the cited operation and constrains the same value,
object state, arithmetic domain, or event sequence on the applicable path.
- Well-known always-on assertion macros (e.g., av_assert0, BUG_ON, ASSERT) are effective
runtime checks, not debug-only no-ops, unless the supplied code shows a disabled definition;
dismissing a visible assertion macro as debug-only is a factual error.
- Before citing a check as decisive counterevidence, instantiate it with the hypothesis's
concrete values: trace the exact variable, length, or index relation the check enforces
across every iteration or accumulation step named in the hypothesis, and verify that it
excludes the claimed violation. A check that is merely related to the cited entities is
not a blocker.
- Before any Vulnerable verdict, consider every condition listed under "Recorded conditions
and allocation/capacity statements referencing cited entities" one by one. In
defenses_considered, list each considered condition with the concrete reason it cannot
block the violation (not dominating the cited operation, path-incompatible, entity
mismatch, or not constraining the hypothesized property). Use an empty list when no such
conditions are shown.
- A value clamped at its origin retains that bound at later uses of the stored value:
`len = min_t(type, *data++, MAX)`, `len = min(len, CAP)`, or an equivalent explicit
`if (len > CAP) len = CAP;` is a dominating same-value bound for subsequent copy/index
operations consuming that stored field, provided no unclamped reassignment intervenes.
Do not reject such a clamp merely because the value originated from untrusted input.
- Preserve each SPx path and object independently. Combine sources only through a cited OPx or
another explicit relation, and never transfer a guard or lifecycle event across branches.
- Use supporting function code only to complete a directly connected call or state transition.
Do not replace the reviewed hypothesis with an unrelated operation from surrounding code.
- Use the most specific supported vulnerability type/CWE. If the evidence supports a different
mechanism at the same cited operation, repair the label and root cause; otherwise reject it.

Evidence-output rules:
- vulnerability_root_cause states the violated invariant and defective operation/control; it
must not merely restate the call path.
- vulnerable_path is the attack path: security-relevant input, transformations, failed or
bypassed control, terminal operation, consequence, and necessary preconditions.
- boundary_status is Established, Plausible, or Unknown. Unknown boundary evidence alone does
not prove safety and must not be replaced by an invented attacker model.
- counterevidence lists only concrete code facts that weaken or defeat the hypothesis.
- proof_gaps lists only material missing facts. Use an empty list when the supplied evidence is
sufficient for the verdict.
- Create an evidence_request only when an exact missing function or macro identifier could
resolve a proof gap. Use one allowed gap_type and the exact identifier in symbol. Do not
request generic repository search, runtime experiments, or code already present.
- confidence is High, Medium, or Low and reflects evidence completeness, not severity.
A material unresolved proof gap is incompatible with High confidence.

Required hypothesis IDs: {required_ids}
{_format_path_scope(task)}
Target function: {task.target_function}
Batching mode: {task.batching_mode}

Concrete operation relations:
{_format_operation_relations(task)}

{operand_section}Independent source-specific TPT subpaths:
{_format_source_subpaths(task)}

Hypotheses to verify:
{_format_hypotheses(task, hypotheses)}

{vec_section}{lifetime_link_section}{macro_section}{limitations_section}Shared relevant code context:
{task.code_context}

Output contract:
{_json_schema_example_verification(required_ids)}

Keep each vulnerability_root_cause concise (prefer <= 120 words) and each vulnerable_path
concise (prefer <= 80 words) so no finding is truncated.
""".strip()



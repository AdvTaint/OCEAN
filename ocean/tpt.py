"""Taint propagation tree construction and path-task packing."""

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
    MAX_PATHS_PER_TARGET_FAMILY,
    MULTI_SOURCE_BATCHING,
    PATH_VARIANT_BATCHING,
    TPT_TREE_ENABLED,
)
from .structures import (
    MultiSourcePathTask,
    SourcePathTask,
    SourceSubpath,
    TaintTreeNode,
)
from .textutil import (
    _source_sink_marker,
    _call_edge_identity,
    _dedup_preserve_order,
    _normalize_code,
    _normalize_space,
    _safe_int,
    _safe_list,
    _source_display,
    _stable_hash,
)


def _group_final_paths(paths: Sequence[List[Dict[str, Any]]]) -> OrderedDict[Tuple[str, str], List[List[Dict[str, Any]]]]:
    groups: OrderedDict[Tuple[str, str], List[List[Dict[str, Any]]]] = OrderedDict()
    for path in paths:
        if not path:
            continue
        first = path[0]
        root = first.get("current_call_chain", ["[unknown]"])[0]
        identity = first.get("source_identity") or _stable_hash({
            "root": root,
            "source": first.get("source_variable"),
            "origin": first.get("taint_source"),
        }, 24)
        groups.setdefault((root, identity), []).append(path)
    return groups


def _fact_from_segment(segment: Dict[str, Any]) -> Dict[str, Any]:
    sink_type = str(segment.get("sink_type", ""))
    event_kind = "CALL_PROPAGATION" if sink_type == "Transitive" else "TERMINAL_OPERATION"
    if sink_type.startswith("Terminal (Depth"):
        event_kind = "DEPTH_LIMITED_OPERATION"
    elif sink_type.startswith("Terminal (Unresolved"):
        event_kind = "UNRESOLVED_PROPAGATION"
    elif segment.get("path_kind") == "block_fallback":
        event_kind = "BLOCK_REVIEW"
    elif segment.get("sink_category") == "Bound-Controlled Index":
        event_kind = "BOUND_CONTROLLED_INDEX"
    elif segment.get("sink_category") == "Scalar Field Flow":
        event_kind = "SCALAR_FIELD_FLOW"
    return {
        "event_kind": event_kind,
        "code": segment.get("sink_operation", ""),
        "controls": sorted(_safe_list(segment.get("control_checks"))),
        # Structured guard facts ride along (excluded from _fact_signature;
        # only used for prompt annotation rendering)
        "guard_facts": _safe_list(segment.get("guard_facts")),
        "event_sequence": _safe_list(segment.get("event_sequence")),
        "function": segment.get("current_call_chain", ["[unknown]"])[-1],
        "sink_type": sink_type,
        "path_kind": segment.get("path_kind", "dataflow"),
        "abstract_object": segment.get("abstract_object"),
        "sink_category": segment.get("sink_category", ""),
        "object_identity": segment.get("object_identity"),
        "evidence_status": segment.get("evidence_status"),
        "start_byte": _safe_int(segment.get("sink_start_byte"), -1),
        "parameter_index": segment.get("parameter_index"),
        "branch_signature": _safe_list(segment.get("branch_signature")),
    }


def _fact_signature(fact: Dict[str, Any]) -> str:
    """Exact fact identity used only for lossless deduplication.

    Source locations are included deliberately. Two identical-looking operations at
    different locations (for example two `free(p)` calls) are distinct evidence and
    must never be collapsed merely because their text matches.
    """
    return json.dumps({
        "event_kind": fact.get("event_kind"),
        "code": _normalize_code(fact.get("code")),
        "controls": sorted(_safe_list(fact.get("controls"))),
        "function": fact.get("function"),
        "path_kind": fact.get("path_kind"),
        "abstract_object": fact.get("abstract_object"),
        "parameter_index": fact.get("parameter_index"),
        "branch_signature": sorted(_safe_list(fact.get("branch_signature"))),
        "path_step": _safe_int(fact.get("path_step"), -1),
        "event_order": _safe_int(fact.get("event_order"), -1),
        "start_byte": _safe_int(fact.get("start_byte"), -1),
    }, sort_keys=True, ensure_ascii=False)


def _sink_signature(sink: Dict[str, Any]) -> str:
    return json.dumps({
        "operation": _normalize_code(sink.get("operation")),
        "controls": sorted(_safe_list(sink.get("controls"))),
        "type": sink.get("type"),
        "function": sink.get("function"),
        "path_kind": sink.get("path_kind"),
        "abstract_object": sink.get("abstract_object"),
        "path_step": _safe_int(sink.get("path_step"), -1),
        "start_byte": _safe_int(sink.get("start_byte"), -1),
        "branch_signature": sorted(_safe_list(sink.get("branch_signature"))),
    }, sort_keys=True, ensure_ascii=False)


def _edge_signature_from_segment(segment: Dict[str, Any], callee: str) -> str:
    explicit = str(segment.get("call_edge_signature") or "").strip()
    if explicit:
        return explicit
    chain = _safe_list(segment.get("current_call_chain"))
    caller = chain[-1] if chain else "[unknown]"
    return _call_edge_identity(
        caller,
        callee,
        segment.get("sink_start_byte", -1),
        segment.get("sink_operation"),
        segment.get("control_checks"),
    )


def _path_terminal_provenance_key(path: Sequence[Dict[str, Any]]) -> str:
    if not path:
        return "sink:empty"
    terminal = path[-1]
    return _stable_hash({
        "source_identity": path[0].get("source_identity", ""),
        "call_edges": [
            segment.get("call_edge_signature", "")
            for segment in path
            if segment.get("call_edge_signature")
        ],
        "function": (_safe_list(terminal.get("current_call_chain")) or ["[unknown]"])[-1],
        "start_byte": _safe_int(terminal.get("sink_start_byte"), -1),
        "operation": _normalize_code(terminal.get("sink_operation")),
        "sink_type": terminal.get("sink_type", "Terminal"),
        "path_kind": terminal.get("path_kind", "dataflow"),
        "abstract_object": terminal.get("abstract_object"),
        "terminal_controls": sorted(_safe_list(terminal.get("control_checks"))),
        "terminal_branch_signature": sorted(_safe_list(terminal.get("branch_signature"))),
    }, 32)


def _merge_fact_sink_support(existing: Dict[str, Any], sink_key: str) -> None:
    supported = set(_safe_list(existing.get("supported_sink_keys")))
    supported.add(sink_key)
    existing["supported_sink_keys"] = sorted(supported)


def _insert_path_into_tree(root_node: TaintTreeNode, path: Sequence[Dict[str, Any]]) -> None:
    """Insert one source-specific path without mixing sibling call-site facts.

    A transitive call fact belongs to the outgoing call edge, not to the shared caller
    node. Therefore it is stored on the callee child selected by the concrete call-site
    signature. This prevents guards/facts from callsite A leaking into callsite B when
    both have the same caller/callee function names.
    """
    sink_key = _path_terminal_provenance_key(path)
    node = root_node
    for segment_index, segment in enumerate(path):
        chain = segment.get("current_call_chain", [])
        function_name = chain[-1] if chain else root_node.function_name
        if segment_index == 0 and function_name == root_node.function_name:
            current = node
        else:
            predecessor = path[segment_index - 1] if segment_index > 0 else {}
            edge_signature = _edge_signature_from_segment(predecessor, function_name)
            child_key = f"{function_name}@{edge_signature}"
            if child_key not in node.children:
                node.children[child_key] = TaintTreeNode(
                    function_name=function_name,
                    entry_edge_signature=edge_signature,
                )
            current = node.children[child_key]
            node = current

        sink_type = str(segment.get("sink_type", ""))
        fact_owner = current
        # Store the caller-side propagation operation on its exact outgoing edge.
        if sink_type == "Transitive" and segment_index + 1 < len(path):
            next_chain = path[segment_index + 1].get("current_call_chain", [])
            callee = next_chain[-1] if next_chain else str(segment.get("sink_target_function") or "[unknown]")
            edge_signature = _edge_signature_from_segment(segment, callee)
            child_key = f"{callee}@{edge_signature}"
            if child_key not in current.children:
                current.children[child_key] = TaintTreeNode(
                    function_name=callee,
                    entry_edge_signature=edge_signature,
                )
            fact_owner = current.children[child_key]

        # Caller-side argument definitions belong to the same concrete call edge.
        # They are explicit evidence for the callee parameter, not independent sinks.
        for provenance_index, provenance in enumerate(
            _safe_list(segment.get("call_argument_provenance"))
        ):
            fact = dict(provenance)
            fact["path_step"] = segment_index
            fact["event_order"] = provenance_index
            fact["supported_sink_keys"] = [sink_key]
            fact_signature = _fact_signature(fact)
            existing_fact = fact_owner.edge_facts.get(fact_signature)
            if existing_fact is None:
                fact_owner.edge_facts[fact_signature] = fact
            else:
                _merge_fact_sink_support(existing_fact, sink_key)

        # Explicit lifecycle events are ordered facts on the same path/edge.
        for event_index, event in enumerate(_safe_list(segment.get("path_events"))):
            fact = {
                "event_kind": event.get("event_kind", "LIFECYCLE_EVENT"),
                "code": event.get("code", ""),
                "controls": sorted(_safe_list(event.get("controls"))),
                "function": function_name,
                "sink_type": sink_type,
                "path_kind": "lifecycle",
                "abstract_object": event.get("object_id", event.get("abstract_object", segment.get("abstract_object"))),
                "object_id": event.get("object_id", event.get("abstract_object", segment.get("abstract_object"))),
                "alias_id": event.get("alias_id", event.get("variable")),
                "event_id": event.get("event_id"),
                "operation_kind": event.get("operation_kind"),
                "nullable_pointer": event.get("nullable_pointer"),
                "unsafe_disjuncts": _safe_list(event.get("unsafe_disjuncts")),
                "branch_signature": _safe_list(event.get("branch_signature")),
                "sink_category": segment.get("lifecycle_kind", ""),
                "start_byte": _safe_int(event.get("start_byte", event.get("statement_index")), -1),
                "path_step": segment_index,
                "event_order": event_index,
                # Observation-level markers (stale-pointer/release-overlap
                # suspects): rendered so both LLM stages treat the event as
                # incomplete evidence, never as a completed pattern.
                "evidence_status": event.get("evidence_status"),
                "effect_source": event.get("effect_source"),
                "effect_strength": event.get("effect_strength"),
                "ordering_note": event.get("ordering_note"),
                "effect_kind": event.get("effect_kind"),
                "unresolved_callees": _safe_list(event.get("unresolved_callees")),
                "heuristic": event.get("heuristic"),
            }
            fact["supported_sink_keys"] = [sink_key]
            fact_signature = _fact_signature(fact)
            existing_fact = fact_owner.edge_facts.get(fact_signature)
            if existing_fact is None:
                fact_owner.edge_facts[fact_signature] = fact
            else:
                _merge_fact_sink_support(existing_fact, sink_key)

        fact = _fact_from_segment(segment)
        fact["path_step"] = segment_index
        fact["event_order"] = len(_safe_list(segment.get("path_events")))
        fact["supported_sink_keys"] = [sink_key]
        fact_signature = _fact_signature(fact)
        existing_fact = fact_owner.edge_facts.get(fact_signature)
        if existing_fact is None:
            fact_owner.edge_facts[fact_signature] = fact
        else:
            _merge_fact_sink_support(existing_fact, sink_key)

        if sink_type.startswith("Terminal"):
            sink = {
                "operation": segment.get("sink_operation", ""),
                "controls": sorted(_safe_list(segment.get("control_checks"))),
                # Structured guard facts ride along (excluded from _sink_signature;
                # only used for prompt annotation rendering)
                "guard_facts": _safe_list(segment.get("guard_facts")),
                "event_sequence": _safe_list(segment.get("event_sequence")),
                "type": segment.get("sink_type", "Terminal"),
                "function": function_name,
                "path_kind": segment.get("path_kind", "dataflow"),
                "abstract_object": segment.get("abstract_object"),
                "category": segment.get("sink_category", ""),
                "start_byte": _safe_int(segment.get("sink_start_byte"), -1),
                "path_step": segment_index,
                "provenance_key": sink_key,
                "branch_signature": _safe_list(segment.get("branch_signature")),
            }
            signature = _sink_signature(sink)
            if signature not in current.terminal_sinks:
                current.terminal_sinks[signature] = sink
            else:
                existing = current.terminal_sinks[signature]
                existing["controls"] = sorted(set(existing.get("controls", [])) | set(sink["controls"]))


def _source_group_metadata(paths: Sequence[List[Dict[str, Any]]]) -> Dict[str, Any]:
    first = paths[0][0]
    aliases: List[str] = []
    origins: List[str] = []
    source_functions: List[str] = []
    context_modes: List[str] = []
    source_statuses: List[str] = []
    abstract_objects: List[str] = []
    for path in paths:
        for segment in path:
            aliases.extend(_safe_list(segment.get("source_aliases")))
            if segment.get("taint_source"):
                origins.append(segment["taint_source"])
            if segment.get("source_from_function"):
                source_functions.extend(
                    part.strip() for part in str(segment["source_from_function"]).split(",") if part.strip()
                )
            context_modes.append(segment.get("context_mode", "path"))
            source_statuses.append(segment.get("source_status", "precise"))
            if segment.get("abstract_object"):
                abstract_objects.append(segment["abstract_object"])
    # Entry-parameter seeded sources keep the "[Function Entry]" prefix plus an
    # "[Entry Parameter]" marker; neither variant names a defining function.
    source_func = next(
        (x for x in source_functions if not x.startswith("[Function Entry]")),
        None,
    )
    return {
        # Root-segment-first order (paths are walked root -> sink); the
        # display layer caps long lists, so keep the origin names up front.
        "aliases": _dedup_preserve_order(str(x) for x in aliases if x),
        "source_origin": "\n".join(_dedup_preserve_order(origins)) or "Unknown source origin.",
        "source_defining_func": source_func,
        "context_mode": "block_fallback" if "block_fallback" in context_modes else "path",
        "source_status": "precise" if "precise" in source_statuses else "not-identified",
        "abstract_object": abstract_objects[0] if abstract_objects else None,
        "source_identity": first.get("source_identity", ""),
    }


def _build_tpt_tasks_for_group(
    root_func: str,
    paths: Sequence[List[Dict[str, Any]]],
    call_graph_diagnostics: Dict[str, Any],
) -> List[SourcePathTask]:
    metadata = _source_group_metadata(paths)

    tasks: List[SourcePathTask] = []
    task_counter = 0

    def dfs(
        node: TaintTreeNode,
        chain: List[str],
        edge_chain: List[str],
        inherited_facts: List[Dict[str, Any]],
    ) -> None:
        nonlocal task_counter
        current_chain = chain if chain and chain[-1] == node.function_name else chain + [node.function_name]
        current_edge_chain = list(edge_chain)
        if node.entry_edge_signature != "ROOT":
            current_edge_chain.append(node.entry_edge_signature)
        current_facts = inherited_facts + list(node.edge_facts.values())
        current_facts = _dedup_facts(current_facts)

        if node.terminal_sinks:
            task_counter += 1
            facts = []
            for index, fact in enumerate(current_facts, start=1):
                item = dict(fact)
                item["fact_id"] = f"F{index}"
                facts.append(item)
            sinks = []
            ordered_sinks = sorted(
                node.terminal_sinks.values(),
                key=lambda item: (
                    _safe_int(item.get("path_step"), -1),
                    _safe_int(item.get("start_byte"), -1),
                    item.get("operation", ""),
                ),
            )
            for index, sink in enumerate(ordered_sinks, start=1):
                item = dict(sink)
                item["sink_id"] = f"S{index}"
                sinks.append(item)

            tasks.append(SourcePathTask(
                task_id=f"{root_func}:{metadata['source_identity']}:{task_counter}",
                root_func=root_func,
                source_identity=metadata["source_identity"],
                source_display=_source_display(metadata["aliases"], metadata["abstract_object"]),
                source_origin=metadata["source_origin"],
                source_defining_func=metadata["source_defining_func"],
                context_mode=metadata["context_mode"],
                source_status=metadata["source_status"],
                call_chain=current_chain,
                exact_call_edges=current_edge_chain,
                target_function=node.function_name,
                facts=facts,
                sinks=sinks,
                call_graph_diagnostics=call_graph_diagnostics,
            ))

        for child in node.children.values():
            dfs(child, current_chain, current_edge_chain, current_facts)

    if TPT_TREE_ENABLED:
        tree = TaintTreeNode(root_func)
        for path in paths:
            _insert_path_into_tree(tree, path)
        dfs(tree, [], [], [])
    else:
        # Ablation A1 (VUL_TPT_TREE=0): no shared prefix tree — each exact
        # path is inserted into its own tree, so prefixes shared by several
        # sinks are re-sent per path instead of rendered once.
        for path in paths:
            solo_tree = TaintTreeNode(root_func)
            _insert_path_into_tree(solo_tree, path)
            dfs(solo_tree, [], [], [])
    return tasks


def _source_task_group_key(task: SourcePathTask) -> Tuple[Any, ...]:
    """Only exact call-path peers share one LLM task."""
    return (
        task.root_func,
        tuple(task.call_chain),
        tuple(task.exact_call_edges),
        task.target_function,
        task.context_mode,
    )


def _concrete_operation_marker(
    function_name: Any,
    start_byte: Any,
    path_step: Any,
    operation: Any,
    controls: Any = None,
    sink_type: Any = "Terminal",
) -> str:
    """Stable concrete-operation identity across source-specific analyses.

    A real source location is the primary identity. Source-specific controls are only
    used when location metadata is unavailable, because the same concrete operation can
    legitimately have different source-specific control summaries.
    """
    normalized_start = _safe_int(start_byte, -1)
    payload: Dict[str, Any] = {
        "function": function_name,
        "start_byte": normalized_start,
        "operation": _normalize_code(operation),
    }
    if normalized_start < 0:
        payload.update({
            "path_step": _safe_int(path_step, -1),
            "controls": sorted(_safe_list(controls)),
            "type": sink_type,
        })
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _renumber_multisource_task(task: MultiSourcePathTask) -> MultiSourcePathTask:
    """Assign stable IDs and translate fact provenance into concrete sink IDs."""
    operation_ids: OrderedDict[str, str] = OrderedDict()
    normalized_subpaths: List[SourceSubpath] = []

    for subpath_index, original in enumerate(task.source_subpaths, start=1):
        subpath_id = f"SP{subpath_index}"
        source_id = f"SRC{subpath_index}"

        sinks: List[Dict[str, Any]] = []
        provenance_to_sink_id: Dict[str, str] = {}
        for sink_index, sink in enumerate(original.sinks, start=1):
            item = dict(sink)
            sink_id = f"{subpath_id}-S{sink_index}"
            item["sink_id"] = sink_id
            item["source_id"] = source_id
            item["subpath_id"] = subpath_id
            provenance_key = str(item.get("provenance_key") or _stable_hash({
                "source_task_id": original.source_task_id,
                "function": item.get("function"),
                "start_byte": _safe_int(item.get("start_byte"), -1),
                "operation": _normalize_code(item.get("operation")),
                "type": item.get("type"),
            }, 32))
            item["provenance_key"] = provenance_key
            provenance_to_sink_id[provenance_key] = sink_id
            operation_marker = _concrete_operation_marker(
                item.get("function"),
                item.get("start_byte", -1),
                item.get("path_step", -1),
                item.get("operation"),
                item.get("controls"),
                item.get("type", "Terminal"),
            )
            if operation_marker not in operation_ids:
                operation_ids[operation_marker] = f"OP{len(operation_ids) + 1}"
            item["operation_id"] = operation_ids[operation_marker]
            sinks.append(item)

        all_sink_ids = [sink["sink_id"] for sink in sinks]
        sink_to_operation = {sink["sink_id"]: sink.get("operation_id") for sink in sinks}
        facts: List[Dict[str, Any]] = []
        for fact_index, fact in enumerate(original.facts, start=1):
            item = dict(fact)
            item["fact_id"] = f"{subpath_id}-F{fact_index}"
            item["source_id"] = source_id
            item["subpath_id"] = subpath_id
            supported_keys = _safe_list(item.get("supported_sink_keys"))
            supported_ids = _dedup_preserve_order(
                provenance_to_sink_id[key]
                for key in supported_keys
                if key in provenance_to_sink_id
            )
            # Stable provenance keys take precedence over local SPx/Sx IDs, which
            # are renumbered when path families are merged. Reuse old IDs only for
            # legacy or synthetic facts that genuinely have no provenance keys.
            if not supported_ids and not supported_keys:
                existing_ids = [
                    sink_id for sink_id in _safe_list(item.get("supported_sink_ids"))
                    if sink_id in all_sink_ids
                ]
                supported_ids = existing_ids or list(all_sink_ids)
            item["supported_sink_ids"] = supported_ids
            item["supported_operation_ids"] = _dedup_preserve_order(
                sink_to_operation[sink_id]
                for sink_id in supported_ids
                if sink_to_operation.get(sink_id)
            )
            facts.append(item)

        normalized_subpaths.append(SourceSubpath(
            subpath_id=subpath_id,
            source_id=source_id,
            source_task_id=original.source_task_id,
            source_identity=original.source_identity,
            source_display=original.source_display,
            source_origin=original.source_origin,
            source_defining_func=original.source_defining_func,
            context_mode=original.context_mode,
            source_status=original.source_status,
            facts=facts,
            sinks=sinks,
            path_root_func=original.path_root_func,
            path_call_chain=list(original.path_call_chain),
            path_call_edges=list(original.path_call_edges),
        ))

    task.source_subpaths = normalized_subpaths
    return task


def _source_task_operation_markers(task: SourcePathTask) -> Set[str]:
    """Concrete terminal-operation identities used for safe multi-source batching."""
    markers: Set[str] = set()
    for sink in task.sinks:
        operation = _normalize_code(sink.get("operation"))
        # Block fallback is intentionally source-local; the synthetic operation is not
        # evidence that unrelated sources participate in one concrete sink.
        if task.context_mode == "block_fallback" or operation == "[Block-Level Review]":
            markers.add(f"fallback:{task.task_id}")
            continue
        marker = _concrete_operation_marker(
            sink.get("function", task.target_function),
            sink.get("start_byte", -1),
            sink.get("path_step", -1),
            operation,
            sink.get("controls"),
            sink.get("type", "Terminal"),
        )
        markers.add(marker)
    return markers


def _source_task_components(peers: Sequence[SourcePathTask]) -> List[List[SourcePathTask]]:
    """Create no-drop source components under the configured batching policy."""
    peers = list(peers)
    if not peers:
        return []
    if MULTI_SOURCE_BATCHING == "off":
        return [[peer] for peer in peers]
    if MULTI_SOURCE_BATCHING == "path":
        return [peers]

    # Default: source-operation bipartite connectivity. Sources join one task only
    # when they share a concrete terminal operation, directly or through another
    # source that reaches multiple concrete operations. This preserves joint
    # buffer/length/capacity reasoning without mixing unrelated same-path sources.
    parent = list(range(len(peers)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    marker_owner: Dict[str, int] = {}
    for index, peer in enumerate(peers):
        for marker in _source_task_operation_markers(peer):
            previous = marker_owner.get(marker)
            if previous is None:
                marker_owner[marker] = index
            else:
                union(previous, index)

    components: OrderedDict[int, List[SourcePathTask]] = OrderedDict()
    for index, peer in enumerate(peers):
        components.setdefault(find(index), []).append(peer)
    return list(components.values())


_SOURCE_MERGE_EXCLUDED_ORIGINS = frozenset({"", "Unknown source origin."})


def _same_source_merge_key(peer: SourcePathTask) -> Optional[Tuple[Any, ...]]:
    """Narrow same-source merge key, or None when merging is not provably safe.

    Two source-specific tasks with the same whitespace-normalized origin text,
    defining function, context mode and source status are two alias spellings of
    one source (for example `packet_len` and its alias `socket_packet` seeded
    from the same definition). Rendering them as separate subpaths only
    duplicates evidence and splits the model's attention, so they are merged
    into one subpath. Unresolved origins are never merged.
    """
    origin = _normalize_space(str(peer.source_origin or ""))
    if origin in _SOURCE_MERGE_EXCLUDED_ORIGINS:
        return None
    return (origin, peer.source_defining_func, peer.context_mode, peer.source_status)


def _merge_same_source_peers(
    peers: Sequence[SourcePathTask],
) -> List[Tuple[List[SourcePathTask], List[Dict[str, Any]], List[Dict[str, Any]]]]:
    """Group same-origin peers into units of (unit_peers, merged_facts, merged_sinks).

    Sink dedup uses the exact evidence signature (location included); collapsed
    duplicates union their controls and remap provenance keys so fact support
    stays resolvable. Fact dedup uses the exact fact signature and unions sink
    support across alias spellings. Unit order follows first appearance.
    """
    units: List[List[SourcePathTask]] = []
    unit_index: Dict[Tuple[Any, ...], int] = {}
    for peer in peers:
        key = _same_source_merge_key(peer)
        if key is not None and key in unit_index:
            units[unit_index[key]].append(peer)
            continue
        if key is not None:
            unit_index[key] = len(units)
        units.append([peer])

    merged_units: List[Tuple[List[SourcePathTask], List[Dict[str, Any]], List[Dict[str, Any]]]] = []
    for unit in units:
        if len(unit) == 1:
            peer = unit[0]
            merged_units.append((
                unit,
                [dict(fact) for fact in peer.facts],
                [dict(sink) for sink in peer.sinks],
            ))
            continue

        sinks: List[Dict[str, Any]] = []
        sink_by_signature: Dict[str, Dict[str, Any]] = {}
        provenance_rewrite: Dict[str, str] = {}
        for peer in unit:
            for sink in peer.sinks:
                item = dict(sink)
                signature = _sink_signature(item)
                existing = sink_by_signature.get(signature)
                if existing is None:
                    item["contributing_source_task_ids"] = [peer.task_id]
                    sink_by_signature[signature] = item
                    sinks.append(item)
                    continue
                existing["controls"] = sorted(
                    set(_safe_list(existing.get("controls"))) | set(_safe_list(item.get("controls")))
                )
                contributors = existing.setdefault("contributing_source_task_ids", [])
                if peer.task_id not in contributors:
                    contributors.append(peer.task_id)
                dropped_key = str(item.get("provenance_key") or "")
                kept_key = str(existing.get("provenance_key") or "")
                if dropped_key and kept_key and dropped_key != kept_key:
                    provenance_rewrite[dropped_key] = kept_key

        facts: List[Dict[str, Any]] = []
        fact_by_signature: Dict[str, Dict[str, Any]] = {}
        for peer in unit:
            for fact in peer.facts:
                item = dict(fact)
                item["supported_sink_keys"] = _dedup_preserve_order(
                    provenance_rewrite.get(str(key), str(key))
                    for key in _safe_list(item.get("supported_sink_keys"))
                )
                signature = _fact_signature(item)
                existing = fact_by_signature.get(signature)
                if existing is None:
                    fact_by_signature[signature] = item
                    facts.append(item)
                    continue
                merged_support = set(_safe_list(existing.get("supported_sink_keys")))
                merged_support.update(_safe_list(item.get("supported_sink_keys")))
                existing["supported_sink_keys"] = sorted(merged_support)
        merged_units.append((unit, facts, sinks))
    return merged_units


def _pack_source_path_tasks(source_tasks: Sequence[SourcePathTask]) -> List[MultiSourcePathTask]:
    """
    Batch only after every source-specific TPT path has been independently built.

    Under the default `operation` mode, exact-path peers are further separated into
    source-operation connected components. Static evidence remains source-isolated,
    and every source-specific task is assigned exactly once.
    """
    exact_path_groups: OrderedDict[Tuple[Any, ...], List[SourcePathTask]] = OrderedDict()
    for source_task in source_tasks:
        exact_path_groups.setdefault(_source_task_group_key(source_task), []).append(source_task)

    packed: List[MultiSourcePathTask] = []
    assigned_source_task_ids: List[str] = []
    task_index = 0
    for (root_func, call_chain, exact_call_edges, target_function, _), peers in exact_path_groups.items():
        for component in _source_task_components(peers):
            task_index += 1
            merged_units = _merge_same_source_peers(component)
            provisional_subpaths = [
                SourceSubpath(
                    subpath_id="",
                    source_id="",
                    source_task_id=unit[0].task_id,
                    source_identity=unit[0].source_identity,
                    source_display=unit[0].source_display,
                    source_origin=unit[0].source_origin,
                    source_defining_func=unit[0].source_defining_func,
                    context_mode=unit[0].context_mode,
                    source_status=unit[0].source_status,
                    facts=unit_facts,
                    sinks=unit_sinks,
                    path_root_func=unit[0].root_func,
                    path_call_chain=list(unit[0].call_chain),
                    path_call_edges=list(unit[0].exact_call_edges),
                )
                for unit, unit_facts, unit_sinks in merged_units
            ]
            shared_markers: Set[str] = set()
            if len(component) > 1:
                counts = Counter(
                    marker
                    for peer in component
                    for marker in _source_task_operation_markers(peer)
                )
                shared_markers = {marker for marker, count in counts.items() if count > 1}

            packed_task = MultiSourcePathTask(
                task_id=(
                    f"PATH-{task_index}-"
                    f"{_stable_hash([root_func, list(call_chain), list(exact_call_edges), target_function, [p.task_id for p in component]], 10)}"
                ),
                root_func=root_func,
                call_chain=list(call_chain),
                exact_call_edges=list(exact_call_edges),
                target_function=target_function,
                source_subpaths=provisional_subpaths,
                call_graph_diagnostics=component[0].call_graph_diagnostics,
                batching_mode=MULTI_SOURCE_BATCHING,
                shared_operation_markers=sorted(shared_markers),
            )
            packed.append(_renumber_multisource_task(packed_task))
            assigned_source_task_ids.extend(peer.task_id for peer in component)

    expected_ids = [task.task_id for task in source_tasks]
    if Counter(assigned_source_task_ids) != Counter(expected_ids):
        raise RuntimeError("Operation-aware source batching lost or duplicated a source-specific path task.")
    return packed


def _common_prefix(values: Sequence[Sequence[str]]) -> List[str]:
    sequences = [list(value) for value in values if value]
    if not sequences:
        return []
    prefix = list(sequences[0])
    for sequence in sequences[1:]:
        limit = min(len(prefix), len(sequence))
        index = 0
        while index < limit and prefix[index] == sequence[index]:
            index += 1
        prefix = prefix[:index]
        if not prefix:
            break
    return prefix


def _pack_terminal_function_variants(
    tasks: Sequence[MultiSourcePathTask],
) -> List[MultiSourcePathTask]:
    """Share target-function context while retaining every exact path as an SP variant."""
    if PATH_VARIANT_BATCHING == "off":
        return list(tasks)

    groups: OrderedDict[Tuple[Any, ...], List[MultiSourcePathTask]] = OrderedDict()
    for task in tasks:
        context_modes = tuple(sorted({sp.context_mode for sp in task.source_subpaths}))
        if "block_fallback" in context_modes:
            key = ("fallback", task.task_id)
        elif MULTI_SOURCE_BATCHING == "off":
            # Ablation (VUL_MULTI_SOURCE_BATCHING=off): cross-source joint context
            # is disabled upstream, so target-function packing must not re-merge
            # different sources into one prompt task. Path variants of the SAME
            # source still share the target-function context, keeping path
            # packing itself out of the ablated variable.
            key = (
                "target",
                task.target_function,
                context_modes,
                tuple(sorted({sp.source_identity for sp in task.source_subpaths})),
            )
        else:
            key = ("target", task.target_function, context_modes)
        groups.setdefault(key, []).append(task)

    output: List[MultiSourcePathTask] = []
    family_index = 0
    for group in groups.values():
        # Budget-aware pre-aggregation: merge paths into one family only while
        # the subpath count stays bounded. A mega-family is otherwise built in
        # full and then expensively degraded/split by _fit_task_to_prompt_budget
        # (the fit loop re-renders the whole family per profile). Pre-chunking
        # keeps families near their final prompt size; the fit/split machinery
        # remains as the safety net for individually oversized families.
        current: List[MultiSourcePathTask] = []
        current_subpaths = 0
        chunks: List[List[MultiSourcePathTask]] = []
        for task in group:
            task_subpaths = len(task.source_subpaths)
            if (
                current
                and current_subpaths + task_subpaths > MAX_PATHS_PER_TARGET_FAMILY
            ):
                chunks.append(current)
                current = []
                current_subpaths = 0
            current.append(task)
            current_subpaths += task_subpaths
        if current:
            chunks.append(current)

        for chunk in chunks:
            family_index += 1
            family = chunk
            if len(family) == 1:
                output.append(family[0])
                continue
            subpaths = [subpath for task in family for subpath in task.source_subpaths]
            path_chains = [
                _subpath_call_chain(task, subpath)
                for task in family for subpath in task.source_subpaths
            ]
            path_edges = [
                _subpath_call_edges(task, subpath)
                for task in family for subpath in task.source_subpaths
            ]
            roots = _dedup_preserve_order(
                subpath.path_root_func or task.root_func
                for task in family for subpath in task.source_subpaths
            )
            target_function = family[0].target_function
            merged = MultiSourcePathTask(
                task_id=(
                    f"TARGET-{family_index}-"
                    f"{_stable_hash([target_function, [task.task_id for task in family]], 10)}"
                ),
                root_func=roots[0] if len(roots) == 1 else "[multiple-roots]",
                call_chain=_common_prefix(path_chains) or [target_function],
                exact_call_edges=_common_prefix(path_edges),
                target_function=target_function,
                source_subpaths=subpaths,
                call_graph_diagnostics=dict(family[0].call_graph_diagnostics),
                batching_mode="target-path-variants",
                shared_operation_markers=sorted({
                    marker for task in family for marker in task.shared_operation_markers
                }),
            )
            output.append(_renumber_multisource_task(merged))

    expected = [
        _source_sink_marker(subpath, sink)
        for task in tasks for subpath in task.source_subpaths for sink in subpath.sinks
    ]
    assigned = [
        _source_sink_marker(subpath, sink)
        for task in output for subpath in task.source_subpaths for sink in subpath.sinks
    ]
    if Counter(assigned) != Counter(expected):
        raise RuntimeError("Target-function path-family batching lost or duplicated evidence.")
    return output


def _all_task_facts(task: MultiSourcePathTask) -> List[Dict[str, Any]]:
    return [fact for subpath in task.source_subpaths for fact in subpath.facts]


def _all_task_sinks(task: MultiSourcePathTask) -> List[Dict[str, Any]]:
    return [sink for subpath in task.source_subpaths for sink in subpath.sinks]


def _task_source_defining_funcs(task: MultiSourcePathTask) -> List[str]:
    return _dedup_preserve_order(
        subpath.source_defining_func
        for subpath in task.source_subpaths
        if subpath.source_defining_func
    )


def _task_source_ids(task: MultiSourcePathTask) -> List[str]:
    return [subpath.source_id for subpath in task.source_subpaths]


def _task_subpath_ids(task: MultiSourcePathTask) -> List[str]:
    return [subpath.subpath_id for subpath in task.source_subpaths]


def _subpath_call_chain(task: MultiSourcePathTask, subpath: SourceSubpath) -> List[str]:
    return list(subpath.path_call_chain or task.call_chain)


def _subpath_call_edges(task: MultiSourcePathTask, subpath: SourceSubpath) -> List[str]:
    return list(subpath.path_call_edges or task.exact_call_edges)


def _task_path_functions(task: MultiSourcePathTask) -> List[str]:
    return _dedup_preserve_order(
        function_name
        for subpath in task.source_subpaths
        for function_name in _subpath_call_chain(task, subpath)
        if function_name
    )


def _task_path_signature(task: MultiSourcePathTask) -> Tuple[Tuple[str, ...], ...]:
    return tuple(sorted({
        tuple(_subpath_call_chain(task, subpath))
        for subpath in task.source_subpaths
    }))


def _dedup_facts(facts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_marker: OrderedDict[str, Dict[str, Any]] = OrderedDict()
    for fact in facts:
        marker = _fact_signature(fact)
        existing = by_marker.get(marker)
        if existing is None:
            by_marker[marker] = dict(fact)
            continue
        for field_name in ("supported_sink_keys", "supported_sink_ids", "supported_operation_ids"):
            existing[field_name] = _dedup_preserve_order(
                _safe_list(existing.get(field_name)) + _safe_list(fact.get(field_name))
            )
    output = list(by_marker.values())
    # Preserve inter-procedural path order. start_byte values are local to each
    # function and must never be compared globally across caller/callee bodies.
    output.sort(key=lambda item: (
        _safe_int(item.get("path_step"), -1),
        _safe_int(item.get("event_order"), -1),
        _safe_int(item.get("start_byte"), -1),
        item.get("function", ""),
        item.get("code", ""),
    ))
    return output



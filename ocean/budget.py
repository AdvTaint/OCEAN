"""Dynamic prompt-budget degradation and task splitting."""

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


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import ContextBuilder

from .config import (
    CONTEXT_CALLEE_DEPTH,
    CONTEXT_CALLER_DEPTH,
    MAX_OPERATIONS_PER_SCREENING_TASK,
    MAX_TOTAL_PROMPT_CHARS,
)
from .prompts import (
    _screening_prompt,
    _task_prompt_fact_count,
)
from .structures import (
    MultiSourcePathTask,
    SourceSubpath,
)
from .textutil import (
    _dedup_preserve_order,
    _normalize_code,
    _prompt_facts_for_subpath,
    _safe_list,
    _source_sink_marker,
)
from .tpt import (
    _all_task_facts,
    _concrete_operation_marker,
    _fact_signature,
    _renumber_multisource_task,
    _subpath_call_chain,
    _subpath_call_edges,
)


def _clone_multisource_task(
    task: MultiSourcePathTask,
    subpaths: Sequence[SourceSubpath],
    index: int,
    total: int,
) -> MultiSourcePathTask:
    clone = MultiSourcePathTask(
        task_id=f"{task.task_id}:chunk{index}",
        root_func=task.root_func,
        call_chain=list(task.call_chain),
        exact_call_edges=list(task.exact_call_edges),
        batching_mode=task.batching_mode,
        shared_operation_markers=list(task.shared_operation_markers),
        target_function=task.target_function,
        source_subpaths=[
            SourceSubpath(
                subpath_id=subpath.subpath_id,
                source_id=subpath.source_id,
                source_task_id=subpath.source_task_id,
                source_identity=subpath.source_identity,
                source_display=subpath.source_display,
                source_origin=subpath.source_origin,
                source_defining_func=subpath.source_defining_func,
                context_mode=subpath.context_mode,
                source_status=subpath.source_status,
                facts=[dict(item) for item in subpath.facts],
                sinks=[dict(item) for item in subpath.sinks],
                path_root_func=subpath.path_root_func,
                path_call_chain=list(subpath.path_call_chain),
                path_call_edges=list(subpath.path_call_edges),
            )
            for subpath in subpaths
        ],
        call_graph_diagnostics=dict(task.call_graph_diagnostics),
        code_context=task.code_context,
        macro_context=task.macro_context,
        selected_caller_depth=task.selected_caller_depth,
        selected_callee_depth=task.selected_callee_depth,
        code_context_mode=task.code_context_mode,
        fact_render_mode=task.fact_render_mode,
        prompt_chunk_index=index,
        prompt_chunk_total=total,
    )
    return _renumber_multisource_task(clone)


def _sink_contributing_task_ids(subpath: SourceSubpath, sink: Dict[str, Any]) -> List[str]:
    """Source tasks whose evidence a (possibly merged) sink stands for."""
    ids = _dedup_preserve_order(
        str(task_id)
        for task_id in _safe_list(sink.get("contributing_source_task_ids"))
        if str(task_id)
    )
    return ids or [subpath.source_task_id]




class PromptBudgetError(RuntimeError):
    pass


def _context_depth_profiles(caller_depth: int, callee_depth: int) -> List[Tuple[int, int]]:
    """Per-task fallback staircase, e.g. 3/4 -> 2/3 -> 1/2 -> 0/1 -> 0/0."""
    if caller_depth < 0 or callee_depth < 0:
        # Unlimited context is a user request, but budget fallback still needs finite
        # profiles. Start with the configured value interpreted as a generous 4.
        caller_depth = 4 if caller_depth < 0 else caller_depth
        callee_depth = 4 if callee_depth < 0 else callee_depth
    profiles: List[Tuple[int, int]] = []
    current_caller = max(0, caller_depth)
    current_callee = max(0, callee_depth)
    while True:
        profile = (current_caller, current_callee)
        if profile not in profiles:
            profiles.append(profile)
        if current_caller == 0 and current_callee == 0:
            break
        current_caller = max(0, current_caller - 1)
        current_callee = max(0, current_callee - 1)
    if profiles[-1] != (0, 0):
        profiles.append((0, 0))
    return profiles


def _apply_prompt_profile(
    task: MultiSourcePathTask,
    context_builder: Optional[ContextBuilder],
    caller_depth: int,
    callee_depth: int,
    code_mode: str,
    fact_mode: str,
) -> int:
    task.selected_caller_depth = caller_depth
    task.selected_callee_depth = callee_depth
    task.code_context_mode = code_mode
    task.fact_render_mode = fact_mode
    if context_builder is not None:
        task.code_context, task.macro_context = context_builder.build(
            task,
            caller_depth=caller_depth,
            callee_depth=callee_depth,
            code_mode=code_mode,
        )
    task.cached_screening_prompt = _screening_prompt(task)
    return len(task.cached_screening_prompt)


def _profile_dropped_mandatory(
    context_builder: Optional[ContextBuilder],
    task: MultiSourcePathTask,
    include_degraded: bool = True,
) -> List[str]:
    """Mandatory path functions missing or snippet-degraded in the last profile.

    "Dropped" (absent entirely) always makes a profile infeasible. "Degraded"
    (body replaced by an evidence-window snippet) is also infeasible by default:
    the omitted lines are exactly where patch-added checks and init-time
    validation live, so emitting such a context manufactures false positives on
    patched code. The last-resort path-variant splitter passes
    include_degraded=False because emitting a degraded context there beats
    losing the whole exact-path variant.
    """
    if context_builder is None:
        return []
    dropped = list(getattr(context_builder, "last_dropped_mandatory", []) or [])
    if dropped:
        # A context missing a mandatory path function must never be emitted
        # silently: warn loudly and let the caller move the budget cascade
        # (compact -> focused -> split) to the next level.
        print(
            f"  - Prompt profile infeasible for {task.task_id}: mandatory path "
            f"function(s) {dropped} missing in code_mode={task.code_context_mode}; "
            "escalating to the next budget cascade level."
        )
    if include_degraded:
        degraded = [
            name
            for name in (getattr(context_builder, "last_degraded_mandatory", []) or [])
            if name not in dropped
        ]
        if degraded:
            print(
                f"  - Prompt profile infeasible for {task.task_id}: mandatory path "
                f"function(s) {degraded} snippet-degraded in "
                f"code_mode={task.code_context_mode}; escalating to splitting "
                "instead of emitting an incomplete function body."
            )
            dropped.extend(degraded)
    return dropped


def _sink_selection_marker(subpath: SourceSubpath, sink: Dict[str, Any]) -> str:
    return _source_sink_marker(subpath, sink)


def _operation_batch_class(operation: Any) -> str:
    """Objective operation class used only to avoid unrelated prompt batching."""
    code = _normalize_code(operation).lower()
    if re.search(r"\b(?:(?:__)?copy_(?:to|from)_user)\s*\(", code):
        return "user-copy"
    if re.search(
        r"\b(?:memcpy|memmove|memset|strcpy|strncpy|strcat|sprintf|snprintf|"
        r"vsprintf|read|recv|fread)\s*\(", code
    ):
        return "bulk-memory"
    if re.search(r"\b(?:free|kfree|delete|list_del\w*|hlist_del\w*|rb_erase)\s*\(", code):
        return "lifetime-state"
    if re.search(r"\b(?:malloc|calloc|realloc|kmalloc|kzalloc|alloc_skb)\s*\(", code):
        return "allocation-state"
    if re.search(r"\b(?:strlen|strnlen|memcmp|strcmp|strncmp|strchr|strrchr)\s*\(", code):
        return "scan-read"
    if re.search(r"\[[^\]]+\]", code):
        return "indexed-access"
    if re.search(r"(?:<<|>>|\+=|-=|\*=|/=|%=|\+\+|--)", code):
        return "numeric-update"
    if re.search(r"\b(?:if|while|for|switch|return|goto)\b", code):
        return "control-state"
    if re.search(r"(?:->|(?<![&])\*(?![=/]))", code):
        return "object-access"
    if re.search(r"\b[A-Za-z_]\w*\s*\(", code):
        return "function-operation"
    return "other-state"


def _operation_sink_families(task: MultiSourcePathTask) -> List[List[List[str]]]:
    """Group concrete operations by neutral operation shape without merging them."""
    families: OrderedDict[str, OrderedDict[str, List[str]]] = OrderedDict()
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            operation_marker = _concrete_operation_marker(
                sink.get("function", task.target_function),
                sink.get("start_byte", -1),
                sink.get("path_step", -1),
                sink.get("operation"),
                sink.get("controls"),
                sink.get("type", "Terminal"),
            )
            family = _operation_batch_class(sink.get("operation"))
            families.setdefault(family, OrderedDict()).setdefault(
                operation_marker, []
            ).append(_sink_selection_marker(subpath, sink))
    return [list(groups.values()) for groups in families.values()]


def _operation_sink_groups(task: MultiSourcePathTask) -> List[List[str]]:
    groups: OrderedDict[str, List[str]] = OrderedDict()
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            operation_marker = _concrete_operation_marker(
                sink.get("function", task.target_function),
                sink.get("start_byte", -1),
                sink.get("path_step", -1),
                sink.get("operation"),
                sink.get("controls"),
                sink.get("type", "Terminal"),
            )
            groups.setdefault(operation_marker, []).append(_sink_selection_marker(subpath, sink))
    return list(groups.values())


def _clone_task_with_selected_sinks(
    task: MultiSourcePathTask,
    selected_markers: Set[str],
    index: int,
    total: int,
) -> MultiSourcePathTask:
    selected_subpaths: List[SourceSubpath] = []
    for subpath in task.source_subpaths:
        selected_sinks = [
            dict(sink) for sink in subpath.sinks
            if _sink_selection_marker(subpath, sink) in selected_markers
        ]
        if not selected_sinks:
            continue
        selected_provenance = {
            str(sink.get("provenance_key") or "")
            for sink in selected_sinks
            if sink.get("provenance_key")
        }
        selected_sink_ids = {str(sink.get("sink_id") or "") for sink in selected_sinks}
        selected_facts: List[Dict[str, Any]] = []
        for fact in subpath.facts:
            supported_keys = set(str(item) for item in _safe_list(fact.get("supported_sink_keys")) if item)
            supported_ids = set(str(item) for item in _safe_list(fact.get("supported_sink_ids")) if item)
            # Provenance is produced at TPT insertion time. Legacy/synthetic facts with
            # no provenance are retained conservatively for every chunk.
            if supported_keys and selected_provenance and supported_keys.isdisjoint(selected_provenance):
                continue
            if not supported_keys and supported_ids and supported_ids.isdisjoint(selected_sink_ids):
                continue
            selected_facts.append(dict(fact))

        selected_subpaths.append(SourceSubpath(
            subpath_id=subpath.subpath_id,
            source_id=subpath.source_id,
            source_task_id=subpath.source_task_id,
            source_identity=subpath.source_identity,
            source_display=subpath.source_display,
            source_origin=subpath.source_origin,
            source_defining_func=subpath.source_defining_func,
            context_mode=subpath.context_mode,
            source_status=subpath.source_status,
            facts=selected_facts,
            sinks=selected_sinks,
            path_root_func=subpath.path_root_func,
            path_call_chain=list(subpath.path_call_chain),
            path_call_edges=list(subpath.path_call_edges),
        ))
    clone = MultiSourcePathTask(
        task_id=f"{task.task_id}:chunk{index}",
        root_func=task.root_func,
        call_chain=list(task.call_chain),
        exact_call_edges=list(task.exact_call_edges),
        batching_mode=task.batching_mode,
        shared_operation_markers=list(task.shared_operation_markers),
        target_function=task.target_function,
        source_subpaths=selected_subpaths,
        call_graph_diagnostics=dict(task.call_graph_diagnostics),
        selected_caller_depth=task.selected_caller_depth,
        selected_callee_depth=task.selected_callee_depth,
        code_context_mode=task.code_context_mode,
        fact_render_mode=task.fact_render_mode,
        prompt_chunk_index=index,
        prompt_chunk_total=total,
    )
    return _renumber_multisource_task(clone)


def _sink_fact_support_map(task: MultiSourcePathTask) -> Dict[str, Set[str]]:
    support: Dict[str, Set[str]] = defaultdict(set)
    for subpath in task.source_subpaths:
        sink_keys = {
            str(sink.get("sink_id")): str(sink.get("provenance_key") or sink.get("sink_id"))
            for sink in subpath.sinks
        }
        all_sink_ids = set(sink_keys)
        for fact in _prompt_facts_for_subpath(subpath):
            supported_ids = set(
                sink_id for sink_id in _safe_list(fact.get("supported_sink_ids"))
                if sink_id in all_sink_ids
            ) or all_sink_ids
            marker = _fact_signature(fact)
            for sink_id in supported_ids:
                support[sink_keys[sink_id]].add(marker)
    return support


def _split_by_complete_path_variants(
    task: MultiSourcePathTask,
    context_builder: Optional[ContextBuilder],
) -> List[MultiSourcePathTask]:
    """Split one oversized operation family without separating same-path sources."""
    units: OrderedDict[Tuple[Any, ...], List[SourceSubpath]] = OrderedDict()
    for subpath in task.source_subpaths:
        key = (
            subpath.path_root_func or task.root_func,
            tuple(_subpath_call_chain(task, subpath)),
            tuple(_subpath_call_edges(task, subpath)),
        )
        units.setdefault(key, []).append(subpath)

    chunks: List[List[SourceSubpath]] = []
    current: List[SourceSubpath] = []
    for unit in units.values():
        candidate = current + unit
        probe = _clone_multisource_task(task, candidate, 1, 1)
        size = _apply_prompt_profile(
            probe, context_builder, 0, 0, "evidence_only", "ultra"
        )
        # Last resort: snippet degradation is accepted here, so only a fully
        # missing mandatory function blocks merging two complete variants.
        probe_infeasible = bool(_profile_dropped_mandatory(
            context_builder, probe, include_degraded=False
        ))
        if current and (size > MAX_TOTAL_PROMPT_CHARS or probe_infeasible):
            chunks.append(current)
            current = list(unit)
        else:
            current = candidate
    if current:
        chunks.append(current)

    output: List[MultiSourcePathTask] = []
    for index, subpaths in enumerate(chunks, start=1):
        chunk = _clone_multisource_task(task, subpaths, index, len(chunks))
        size = _apply_prompt_profile(
            chunk, context_builder, 0, 0, "evidence_only", "ultra"
        )
        if size > MAX_TOTAL_PROMPT_CHARS:
            raise PromptBudgetError(
                f"One complete exact-path variant for {task.task_id} exceeds the prompt "
                f"budget after lossless compaction: {size}>{MAX_TOTAL_PROMPT_CHARS}."
            )
        # Last resort: a single complete variant cannot be split further. The
        # loud infeasibility warning has already been printed; emitting the
        # compacted context beats losing the whole exact-path variant.
        _profile_dropped_mandatory(context_builder, chunk, include_degraded=False)
        output.append(chunk)
    return output


def _split_by_operation_attention_budget(
    task: MultiSourcePathTask,
) -> List[MultiSourcePathTask]:
    """Bound unrelated operations while preserving every source-operation family."""
    operation_families = _operation_sink_families(task)
    operation_count = sum(len(family) for family in operation_families)
    if operation_count <= MAX_OPERATIONS_PER_SCREENING_TASK:
        return [task]

    marker_chunks: List[List[str]] = []
    for family in operation_families:
        for start in range(0, len(family), MAX_OPERATIONS_PER_SCREENING_TASK):
            marker_chunks.append([
                marker
                for operation_group in family[
                    start:start + MAX_OPERATIONS_PER_SCREENING_TASK
                ]
                for marker in operation_group
            ])
    chunks = [
        _clone_task_with_selected_sinks(
            task, set(markers), index, len(marker_chunks)
        )
        for index, markers in enumerate(marker_chunks, start=1)
    ]

    expected = [
        _source_sink_marker(subpath, sink)
        for subpath in task.source_subpaths
        for sink in subpath.sinks
    ]
    assigned = [
        _source_sink_marker(subpath, sink)
        for chunk in chunks
        for subpath in chunk.source_subpaths
        for sink in subpath.sinks
    ]
    if Counter(assigned) != Counter(expected):
        raise RuntimeError(
            f"Operation-attention splitting lost or duplicated source-sink evidence for {task.task_id}."
        )

    original_support = _sink_fact_support_map(task)
    assigned_support: Dict[str, Set[str]] = defaultdict(set)
    for chunk in chunks:
        for sink_key, fact_markers in _sink_fact_support_map(chunk).items():
            assigned_support[sink_key].update(fact_markers)
    for sink_key, fact_markers in original_support.items():
        if not fact_markers.issubset(assigned_support.get(sink_key, set())):
            raise RuntimeError(
                f"Operation-attention splitting lost supporting facts for {sink_key} in {task.task_id}."
            )

    print(
        f"  - Operation-attention split: {task.task_id}, "
        f"operations={operation_count} -> {len(chunks)} semantic tasks; "
        f"max_operations={MAX_OPERATIONS_PER_SCREENING_TASK}; no evidence dropped."
    )
    return chunks


def _fit_task_to_prompt_budget(
    task: MultiSourcePathTask,
    context_builder: Optional[ContextBuilder] = None,
) -> List[MultiSourcePathTask]:
    """Fit one terminal-function family without deleting path or sink evidence.

    Degradation order:
    1. Reduce path-external caller/callee context depth per task.
    2. Deduplicate guard rendering and use compact fact serialization.
    3. Replace full functions with exact-path evidence snippets.
    4. Split by complete concrete-operation groups.
    5. If one operation remains oversized, split only by complete exact-path variants.
    """
    profiles = _context_depth_profiles(CONTEXT_CALLER_DEPTH, CONTEXT_CALLEE_DEPTH)
    first_prompt_size: Optional[int] = None

    # Stage 1: keep full facts and full code, reducing only extra graph neighbors.
    for caller_depth, callee_depth in profiles:
        prompt_size = _apply_prompt_profile(
            task, context_builder, caller_depth, callee_depth, "full", "full"
        )
        if first_prompt_size is None:
            first_prompt_size = prompt_size
        if _profile_dropped_mandatory(context_builder, task):
            continue
        if prompt_size <= MAX_TOTAL_PROMPT_CHARS:
            if (caller_depth, callee_depth) != profiles[0]:
                print(
                    f"  - Prompt budget reduced external context for {task.task_id}: "
                    f"{profiles[0][0]}/{profiles[0][1]} -> {caller_depth}/{callee_depth}; "
                    f"chars={prompt_size}."
                )
            return [task]

    final_caller, final_callee = profiles[-1]
    # Snippet tiers ("minimal"/"evidence_only") are deliberately absent: they
    # only ever fit by degrading path-function bodies, which the degraded-
    # mandatory guard now rejects. Oversized families go straight to splitting.
    compact_profiles = [
        ("full", "compact"),
        ("focused", "compact"),
    ]
    for code_mode, fact_mode in compact_profiles:
        prompt_size = _apply_prompt_profile(
            task,
            context_builder,
            final_caller,
            final_callee,
            code_mode,
            fact_mode,
        )
        if _profile_dropped_mandatory(context_builder, task):
            continue
        if prompt_size <= MAX_TOTAL_PROMPT_CHARS:
            print(
                f"  - Prompt budget compacted {task.task_id}: "
                f"context={final_caller}/{final_callee}, code={code_mode}, facts={fact_mode}, "
                f"raw_facts={len(_all_task_facts(task))}, "
                f"path_spine_facts={_task_prompt_fact_count(task)}, chars={prompt_size}."
            )
            return [task]

    # Stage 4: split by complete concrete operation groups, never by one arbitrary sink.
    operation_groups = _operation_sink_groups(task)
    chunks_markers: List[List[str]] = []
    current_markers: List[str] = []
    for operation_group in operation_groups:
        candidate_markers = current_markers + operation_group
        probe = _clone_task_with_selected_sinks(
            task, set(candidate_markers), 1, 1
        )
        probe_size = _apply_prompt_profile(
            probe,
            context_builder,
            0,
            0,
            "focused",
            "compact",
        )
        probe_infeasible = bool(_profile_dropped_mandatory(context_builder, probe))
        if current_markers and (
            probe_size > MAX_TOTAL_PROMPT_CHARS or probe_infeasible
        ):
            chunks_markers.append(current_markers)
            current_markers = list(operation_group)
        else:
            current_markers = candidate_markers
    if current_markers:
        chunks_markers.append(current_markers)

    result: List[MultiSourcePathTask] = []
    for index, marker_group in enumerate(chunks_markers, start=1):
        chunk = _clone_task_with_selected_sinks(
            task, set(marker_group), index, len(chunks_markers)
        )
        prompt_size = _apply_prompt_profile(
            chunk,
            context_builder,
            0,
            0,
            "focused",
            "compact",
        )
        chunk_infeasible = bool(_profile_dropped_mandatory(context_builder, chunk))
        if prompt_size > MAX_TOTAL_PROMPT_CHARS or chunk_infeasible:
            result.extend(_split_by_complete_path_variants(chunk, context_builder))
        else:
            result.append(chunk)

    expected = [
        _source_sink_marker(subpath, sink)
        for subpath in task.source_subpaths
        for sink in subpath.sinks
    ]
    assigned = [
        _source_sink_marker(subpath, sink)
        for chunk in result
        for subpath in chunk.source_subpaths
        for sink in subpath.sinks
    ]
    if Counter(assigned) != Counter(expected):
        raise RuntimeError(f"Prompt-budget splitting lost or duplicated source-sink evidence for {task.task_id}.")

    original_support = _sink_fact_support_map(task)
    assigned_support: Dict[str, Set[str]] = defaultdict(set)
    for chunk in result:
        for sink_key, fact_markers in _sink_fact_support_map(chunk).items():
            assigned_support[sink_key].update(fact_markers)
    for sink_key, fact_markers in original_support.items():
        if not fact_markers.issubset(assigned_support.get(sink_key, set())):
            missing = sorted(fact_markers - assigned_support.get(sink_key, set()))
            raise RuntimeError(
                f"Prompt-budget splitting lost {len(missing)} supporting fact(s) for "
                f"sink provenance {sink_key} in {task.task_id}."
            )

    print(
        f"  - Operation-group prompt split after adaptive compaction: {task.task_id}, "
        f"initial_chars={first_prompt_size}, raw_facts={len(_all_task_facts(task))}, "
        f"path_spine_facts={_task_prompt_fact_count(task)}, sinks={len(expected)} -> "
        f"{len(result)} chunks; every complete operation and path spine retained."
    )
    return result



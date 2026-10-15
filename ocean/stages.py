"""Screening and verification invocation, proof-gap completion, aggregation."""

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

from .sast_backend import (
    extract_relevant_macro_definitions,
)

from .budget import (
    PromptBudgetError,
    _clone_multisource_task,
)
from .config import (
    ALLOW_MODEL_JSON_REPAIR,
    ANALYZER_MISSING_BATCH_RETRY,
    ANALYZER_MISSING_SINGLE_RETRY,
    DEBUG_ANALYZER_RAW,
    DEBUG_SCREENER_RAW,
    INCLUDE_REJECTED_FINDINGS,
    MAX_PROOF_GAP_EVIDENCE_CHARS,
    MAX_PROOF_GAP_SYMBOLS,
    MAX_TOTAL_PROMPT_CHARS,
    MAX_VERIFICATION_PROMPT_CHARS,
    PREVERIFY_EXACT_DEDUP,
    PROOF_GAP_EXPANSION,
    REVIEW_MODE,
    SCREENER_STATIC_RESCUE,
    _analyzer_text_llm,
    _screener_text_llm,
)
from .context import (
    ContextBuilder,
)
from .engine import (
    StaticAnalysisEngine,
    _disjunctive_null_guard_facts,
)
from .prompts import (
    _format_lifecycle_backedge_relations,
    _screening_prompt,
    _task_prompt_fact_count,
    _verification_prompt,
)
from .schemas import (
    PUBLIC_FINDING_FIELDS,
    ScreeningResult,
    VerificationResult,
    _SCREENING_FIXER,
    _SCREENING_NATIVE,
    _SCREENING_PARSER,
    _VERIFICATION_FIXER,
    _VERIFICATION_NATIVE,
    _VERIFICATION_PARSER,
)
from .structures import (
    AnalyzerTask,
    MultiSourcePathTask,
    SourceSubpath,
)
from .textutil import (
    _call_arguments,
    _meaningful_label,
    _split_call_arguments,
    _target_function_code,
    _balanced_region,
    _PROOF_GAP_TYPES,
    _canonical_hypothesis_id,
    _coerce_structured_result,
    _dedup_preserve_order,
    _invoke_text_model,
    _message_to_text,
    _model_dump,
    _normalize_code,
    _normalize_finding_evidence_fields,
    _normalize_space,
    _normalize_vulnerability_status,
    _parse_screening_result,
    _parse_verification_result,
    _safe_int,
    _safe_list,
    _stable_hash,
)
from .tpt import (
    _all_task_facts,
    _all_task_sinks,
    _subpath_call_chain,
    _subpath_call_edges,
    _task_source_ids,
    _task_subpath_ids,
)


def _normalize_hypotheses(
    task: MultiSourcePathTask,
    result: ScreeningResult,
) -> List[Dict[str, Any]]:
    valid_source_ids = set(_task_source_ids(task))
    valid_subpath_ids = set(_task_subpath_ids(task))
    facts = _all_task_facts(task)
    sinks = _all_task_sinks(task)
    valid_fact_ids = {fact["fact_id"] for fact in facts}
    valid_sink_ids = {sink["sink_id"] for sink in sinks}
    fact_to_subpath = {fact["fact_id"]: fact.get("subpath_id") for fact in facts}
    sink_to_subpath = {sink["sink_id"]: sink.get("subpath_id") for sink in sinks}
    subpath_to_source = {
        subpath.subpath_id: subpath.source_id
        for subpath in task.source_subpaths
    }
    source_to_subpaths: Dict[str, List[str]] = defaultdict(list)
    for subpath in task.source_subpaths:
        source_to_subpaths[subpath.source_id].append(subpath.subpath_id)

    merged: OrderedDict[str, Dict[str, Any]] = OrderedDict()
    for model_hypothesis in result.hypotheses:
        item = _model_dump(model_hypothesis)
        # Degenerate template hypotheses (empty root cause under constrained
        # decoding) carry no information; drop them before they can consume a
        # verification call.
        if not _normalize_space(item.get("root_cause_hypothesis", "")) and not _normalize_space(
            item.get("suspected_broken_control", "")
        ):
            continue
        item["relevant_source_ids"] = _dedup_preserve_order(
            source_id for source_id in _safe_list(item.get("relevant_source_ids"))
            if source_id in valid_source_ids
        )
        item["relevant_subpath_ids"] = _dedup_preserve_order(
            subpath_id for subpath_id in _safe_list(item.get("relevant_subpath_ids"))
            if subpath_id in valid_subpath_ids
        )
        item["relevant_fact_ids"] = _dedup_preserve_order(
            fact_id for fact_id in _safe_list(item.get("relevant_fact_ids"))
            if fact_id in valid_fact_ids
        )
        item["relevant_sink_ids"] = _dedup_preserve_order(
            sink_id for sink_id in _safe_list(item.get("relevant_sink_ids"))
            if sink_id in valid_sink_ids
        )

        inferred_subpaths = _dedup_preserve_order(
            [fact_to_subpath[fact_id] for fact_id in item["relevant_fact_ids"] if fact_to_subpath.get(fact_id)]
            + [sink_to_subpath[sink_id] for sink_id in item["relevant_sink_ids"] if sink_to_subpath.get(sink_id)]
            + [
                subpath_id
                for source_id in item["relevant_source_ids"]
                for subpath_id in source_to_subpaths.get(source_id, [])
            ]
        )
        item["relevant_subpath_ids"] = _dedup_preserve_order(
            item["relevant_subpath_ids"] + inferred_subpaths
        )
        inferred_sources = [
            subpath_to_source[subpath_id]
            for subpath_id in item["relevant_subpath_ids"]
            if subpath_id in subpath_to_source
        ]
        item["relevant_source_ids"] = _dedup_preserve_order(
            item["relevant_source_ids"] + inferred_sources
        )

        # Preserve a credible but poorly formatted hypothesis. With multiple sources,
        # associate all subpaths only as an explicit verifier fallback rather than
        # silently inventing one source relation in the screener stage.
        if not item["relevant_subpath_ids"]:
            item["relevant_subpath_ids"] = _task_subpath_ids(task)
            item["relevant_source_ids"] = _task_source_ids(task)
        if not item["relevant_sink_ids"]:
            referenced = set(item["relevant_subpath_ids"])
            item["relevant_sink_ids"] = [
                sink["sink_id"] for sink in sinks
                if sink.get("subpath_id") in referenced
            ] or sorted(valid_sink_ids)

        root_marker = _normalize_space(item.get("root_cause_hypothesis", "")).lower()
        dedup_key = (
            f"{item.get('cwe_id', '')}|{item.get('potential_vulnerability_type', '')}|"
            f"{root_marker}"
        )
        if dedup_key not in merged:
            merged[dedup_key] = item
        else:
            existing = merged[dedup_key]
            for field_name in (
                "relevant_source_ids",
                "relevant_subpath_ids",
                "relevant_fact_ids",
                "relevant_sink_ids",
            ):
                existing[field_name] = _dedup_preserve_order(
                    _safe_list(existing.get(field_name)) + _safe_list(item.get(field_name))
                )

    normalized = list(merged.values())
    for index, item in enumerate(normalized, start=1):
        item["hypothesis_id"] = f"H{index}"
        item["_preverify_fingerprint"] = _hypothesis_causal_fingerprint(task, item, include_path=True)
        item["_root_cause_fingerprint"] = _hypothesis_causal_fingerprint(task, item, include_path=False)
    return normalized


def _hypothesis_referenced_evidence(
    task: MultiSourcePathTask,
    hypothesis: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    fact_ids = set(_safe_list(hypothesis.get("relevant_fact_ids")))
    sink_ids = set(_safe_list(hypothesis.get("relevant_sink_ids")))
    subpath_ids = set(_safe_list(hypothesis.get("relevant_subpath_ids")))
    facts = [
        fact for fact in _all_task_facts(task)
        if (fact_ids and fact.get("fact_id") in fact_ids)
        or (not fact_ids and fact.get("subpath_id") in subpath_ids)
    ]
    sinks = [
        sink for sink in _all_task_sinks(task)
        if (sink_ids and sink.get("sink_id") in sink_ids)
        or (not sink_ids and sink.get("subpath_id") in subpath_ids)
    ]
    return facts, sinks


def _static_site_marker(item: Dict[str, Any], operation_field: str) -> str:
    return json.dumps({
        "function": item.get("function"),
        "start_byte": _safe_int(item.get("start_byte"), -1),
        "path_step": _safe_int(item.get("path_step"), -1),
        "kind": item.get("event_kind") or item.get("type"),
        "operation": _normalize_code(item.get(operation_field)),
        "object": item.get("object_id") or item.get("abstract_object"),
    }, sort_keys=True, ensure_ascii=False)


def _hypothesis_causal_fingerprint(
    task: MultiSourcePathTask,
    hypothesis: Dict[str, Any],
    include_path: bool,
) -> str:
    facts, sinks = _hypothesis_referenced_evidence(task, hypothesis)
    cwe = _meaningful_label(hypothesis.get("cwe_id"))
    vulnerability_type = _meaningful_label(hypothesis.get("potential_vulnerability_type"))
    class_label = cwe or vulnerability_type or "UNKNOWN"
    lifecycle = class_label in {"CWE-415", "CWE-416"} or any(
        token in vulnerability_type for token in ("USE-AFTER-FREE", "DOUBLE FREE")
    )
    payload: Dict[str, Any] = {
        "class": class_label,
        "sink_sites": sorted(_static_site_marker(sink, "operation") for sink in sinks),
    }
    if lifecycle:
        lifecycle_facts = [
            fact for fact in facts
            if str(fact.get("event_kind") or "").upper() in {
                "ALIAS_CAPTURE", "OBJECT_REFERENCE", "RELEASE", "RELEASE_AGAIN",
                "INVALIDATE", "USE", "REFRESH", "REASSIGN", "OBJECT_REPLACEMENT",
                "OWNERSHIP_TRANSFER", "UNKNOWN_EFFECT",
            }
        ]
        payload.update({
            "objects": sorted({
                str(fact.get("object_id") or fact.get("abstract_object"))
                for fact in lifecycle_facts
                if fact.get("object_id") or fact.get("abstract_object")
            }),
            "events": [
                _static_site_marker(fact, "code")
                for fact in sorted(lifecycle_facts, key=_lifecycle_fact_order)
            ],
        })
        if not lifecycle_facts:
            # State-mediated lifetime hypotheses may share a sink without sharing a
            # cause. Preserve their semantic root instead of collapsing every
            # no-event CWE-416 hypothesis at that operation.
            payload["root_marker"] = _normalize_space(
                hypothesis.get("root_cause_hypothesis", "")
            ).lower()
    else:
        causal_facts = [
            fact for fact in facts
            if str(fact.get("event_kind") or "").upper() not in {
                "CALL_PROPAGATION", "TERMINAL_OPERATION"
            }
        ]
        payload["causal_sites"] = sorted(
            _static_site_marker(fact, "code") for fact in causal_facts
        )
        # Keep the semantic root marker even when the model cites a broad fact set.
        # This makes pre-verification consolidation exact and conservative: two
        # distinct same-CWE causes at one sink are never merged merely because both
        # hypotheses referenced all available facts.
        payload["root_marker"] = _normalize_space(
            hypothesis.get("root_cause_hypothesis", "")
        ).lower()
    if include_path:
        referenced_subpaths = set(_safe_list(hypothesis.get("relevant_subpath_ids")))
        path_variants = [
            {
                "root_func": subpath.path_root_func or task.root_func,
                "call_chain": _subpath_call_chain(task, subpath),
                "exact_call_edges": _subpath_call_edges(task, subpath),
            }
            for subpath in task.source_subpaths
            if not referenced_subpaths or subpath.subpath_id in referenced_subpaths
        ]
        payload.update({"path_variants": path_variants})
    return _stable_hash(payload, 40)


def _lifecycle_evidence_status(task: MultiSourcePathTask, hypothesis: Dict[str, Any]) -> str:
    cwe = _meaningful_label(hypothesis.get("cwe_id"))
    vulnerability_type = _meaningful_label(hypothesis.get("potential_vulnerability_type"))
    expected_kind = "uaf" if cwe == "CWE-416" or "USE-AFTER-FREE" in vulnerability_type else (
        "double_free" if cwe == "CWE-415" or "DOUBLE FREE" in vulnerability_type else ""
    )
    if not expected_kind:
        return "not-lifecycle"
    referenced_subpaths = set(_safe_list(hypothesis.get("relevant_subpath_ids")))
    matching: List[Dict[str, Any]] = []
    for subpath in task.source_subpaths:
        if referenced_subpaths and subpath.subpath_id not in referenced_subpaths:
            continue
        matching.extend(
            chain for chain in _ordered_lifecycle_evidence(subpath)
            if chain.get("kind") == expected_kind
        )
    if matching:
        objects = sorted({str(chain.get("object_id")) for chain in matching})
        return f"ordered same-object {expected_kind} chain present for objects={objects}"

    hypothesis_text = " ".join([
        str(hypothesis.get("root_cause_hypothesis") or ""),
        str(hypothesis.get("suspected_broken_control") or ""),
    ])
    facts, sinks = _hypothesis_referenced_evidence(task, hypothesis)
    evidence_text = " ".join(
        [hypothesis_text]
        + [str(fact.get("code") or "") for fact in facts]
        + [str(sink.get("operation") or "") for sink in sinks]
    )
    has_container_mutation = bool(re.search(
        r"\b(?:list_del(?:_rcu|_init)?|hlist_del(?:_rcu|_init)?|rb_erase)\b",
        evidence_text,
        flags=re.I,
    ))
    claims_repeated_state_transition = bool(re.search(
        r"double[- ]?(?:remove|unlink|delet)|repeated (?:remove|unlink|delet)|"
        r"membership (?:state|check)|check[- ]then[- ]act|flag state",
        hypothesis_text,
        flags=re.I,
    ))
    state_mediated = (
        expected_kind == "uaf"
        and has_container_mutation
        and claims_repeated_state_transition
    )
    if state_mediated:
        return (
            "state-mediated lifecycle candidate present; verify same-object membership, "
            "competing executions, destructive mutation, and synchronization scope"
        )
    return (
        f"static evidence does not yet establish an ordered same-object {expected_kind} chain; "
        "the verifier must not confirm from API names or unordered event presence alone"
    )


def _hypothesis_evidence_score(task: MultiSourcePathTask, hypothesis: Dict[str, Any]) -> Tuple[int, int, int, int]:
    precise_sources = sum(
        1 for subpath in task.source_subpaths
        if subpath.source_id in set(_safe_list(hypothesis.get("relevant_source_ids")))
        and subpath.source_status == "precise"
    )
    return (
        len(_safe_list(hypothesis.get("relevant_fact_ids"))),
        len(_safe_list(hypothesis.get("relevant_sink_ids"))),
        precise_sources,
        len(task.code_context),
    )


def _consolidate_exact_duplicate_hypotheses(
    tasks: Sequence[AnalyzerTask],
) -> List[AnalyzerTask]:
    """Deduplicate only exact static causal fingerprints before verification."""
    if not PREVERIFY_EXACT_DEDUP:
        return list(tasks)
    records: Dict[str, List[Tuple[int, int, AnalyzerTask, Dict[str, Any]]]] = defaultdict(list)
    for task_index, analyzer_task in enumerate(tasks):
        for hypothesis_index, hypothesis in enumerate(analyzer_task.hypotheses):
            fingerprint = str(
                hypothesis.get("_preverify_fingerprint")
                or _hypothesis_causal_fingerprint(analyzer_task.path_task, hypothesis, include_path=True)
            )
            hypothesis["_preverify_fingerprint"] = fingerprint
            hypothesis["_root_cause_fingerprint"] = str(
                hypothesis.get("_root_cause_fingerprint")
                or _hypothesis_causal_fingerprint(analyzer_task.path_task, hypothesis, include_path=False)
            )
            records[fingerprint].append((task_index, hypothesis_index, analyzer_task, hypothesis))

    selected: Dict[int, List[Tuple[int, Dict[str, Any]]]] = defaultdict(list)
    duplicate_count = 0
    for candidates in records.values():
        candidates = sorted(
            candidates,
            key=lambda item: (
                _hypothesis_evidence_score(item[2].path_task, item[3]),
                -item[0],
                -item[1],
            ),
            reverse=True,
        )
        task_index, hypothesis_index, representative_task, representative = candidates[0]
        for _, _, duplicate_task, duplicate in candidates[1:]:
            duplicate_count += 1
            # IDs are task-local. Merge evidence IDs only when both hypotheses belong
            # to the same path task; cross-task namespaces are never transplanted.
            if duplicate_task.path_task.task_id == representative_task.path_task.task_id:
                for field_name in (
                    "relevant_source_ids", "relevant_subpath_ids",
                    "relevant_fact_ids", "relevant_sink_ids",
                ):
                    representative[field_name] = _dedup_preserve_order(
                        _safe_list(representative.get(field_name))
                        + _safe_list(duplicate.get(field_name))
                    )
            if len(str(duplicate.get("root_cause_hypothesis") or "")) > len(str(representative.get("root_cause_hypothesis") or "")):
                representative["root_cause_hypothesis"] = duplicate["root_cause_hypothesis"]
        selected[task_index].append((hypothesis_index, representative))

    consolidated: List[AnalyzerTask] = []
    for task_index, analyzer_task in enumerate(tasks):
        chosen = [item for _, item in sorted(selected.get(task_index, []), key=lambda pair: pair[0])]
        if chosen:
            consolidated.append(AnalyzerTask(path_task=analyzer_task.path_task, hypotheses=chosen))
    if duplicate_count:
        print(
            f"  - Pre-verification exact root-cause consolidation: "
            f"{sum(len(task.hypotheses) for task in tasks)} hypotheses -> "
            f"{sum(len(task.hypotheses) for task in consolidated)}; "
            f"avoided {duplicate_count} duplicate verification verdict(s)."
        )

    # Efficiency B2: after exact dedup, merge only path variants that share the
    # same CWE, concrete sink sites, and static root-cause fingerprint.
    clustered: List[AnalyzerTask] = []
    cluster_saved = 0
    for analyzer_task in consolidated:
        merged, saved = _cluster_same_sink_hypotheses(analyzer_task)
        cluster_saved += saved
        if merged:
            clustered.append(AnalyzerTask(path_task=analyzer_task.path_task, hypotheses=merged))
    if cluster_saved:
        print(
            f"  - Pre-verification causal-path clustering: "
            f"{sum(len(task.hypotheses) for task in consolidated)} hypotheses -> "
            f"{sum(len(task.hypotheses) for task in clustered)}; "
            f"saved {cluster_saved} verification hypothesis(es)."
        )
    return clustered


def _cluster_same_sink_hypotheses(
    analyzer_task: AnalyzerTask,
) -> Tuple[List[Dict[str, Any]], int]:
    """Merge path variants only when they describe the same static root cause.

    A shared CWE and sink are insufficient: one copy operation may have distinct
    read- and write-side violations, and one lifecycle operation may reference
    different object generations. The causal fingerprint preserves those
    distinctions while still allowing equivalent path variants to share one
    verifier hypothesis.
    """
    sink_registry: Dict[str, Dict[str, Any]] = {}
    for subpath in analyzer_task.path_task.source_subpaths:
        for sink in subpath.sinks:
            sink_registry[str(sink.get("sink_id"))] = sink

    groups: OrderedDict[Any, List[Dict[str, Any]]] = OrderedDict()
    for index, hypothesis in enumerate(analyzer_task.hypotheses):
        class_label = (
            _meaningful_label(hypothesis.get("cwe_id"))
            or _meaningful_label(hypothesis.get("potential_vulnerability_type"))
            or "UNKNOWN"
        )
        sink_sites = frozenset(
            _static_site_marker(sink_registry[str(sink_id)], "operation")
            for sink_id in _safe_list(hypothesis.get("relevant_sink_ids"))
            if str(sink_id) in sink_registry
        )
        if not sink_sites:
            # Unanchored hypotheses get a unique key: when in doubt, don't merge.
            key = ("__unique__", index)
        else:
            causal_fingerprint = str(
                hypothesis.get("_root_cause_fingerprint")
                or _hypothesis_causal_fingerprint(
                    analyzer_task.path_task, hypothesis, include_path=False
                )
            )
            hypothesis["_root_cause_fingerprint"] = causal_fingerprint
            key = (
                class_label,
                analyzer_task.path_task.target_function,
                sink_sites,
                causal_fingerprint,
            )
        groups.setdefault(key, []).append(hypothesis)

    merged_output: List[Dict[str, Any]] = []
    saved = 0
    for members in groups.values():
        if len(members) == 1:
            merged_output.extend(members)
            continue
        representative = max(
            members,
            key=lambda item: len(str(item.get("root_cause_hypothesis") or "")),
        )
        for field_name in (
            "relevant_source_ids", "relevant_subpath_ids",
            "relevant_fact_ids", "relevant_sink_ids",
        ):
            representative[field_name] = _dedup_preserve_order(
                value
                for member in members
                for value in _safe_list(member.get(field_name))
            )
        representative["merged_hypothesis_count"] = len(members)
        representative["_preverify_fingerprint"] = _hypothesis_causal_fingerprint(
            analyzer_task.path_task, representative, include_path=True
        )
        saved += len(members) - 1
        merged_output.append(representative)
    return merged_output, saved


def _lifecycle_fact_order(fact: Dict[str, Any]) -> Tuple[int, int, int, str]:
    return (
        _safe_int(fact.get("path_step"), -1),
        _safe_int(fact.get("event_order"), -1),
        _safe_int(fact.get("start_byte"), -1),
        str(fact.get("event_kind") or ""),
    )


def _branch_signatures_may_coexecute(left: Any, right: Any) -> bool:
    left_set = set(str(item) for item in _safe_list(left) if item)
    right_set = set(str(item) for item in _safe_list(right) if item)
    for guard in left_set:
        compact = guard.replace(" ", "")
        if f"!{compact}" in {item.replace(" ", "") for item in right_set}:
            return False
    for guard in right_set:
        compact = guard.replace(" ", "")
        if f"!{compact}" in {item.replace(" ", "") for item in left_set}:
            return False
    return True


def _ordered_lifecycle_evidence(subpath: SourceSubpath) -> List[Dict[str, Any]]:
    """Return same-object ordered lifecycle chains; never join different objects."""
    by_object: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for fact in subpath.facts:
        kind = str(fact.get("event_kind") or "").upper()
        if kind not in {
            "ALIAS_CAPTURE", "OBJECT_REFERENCE", "RELEASE", "RELEASE_AGAIN",
            "INVALIDATE", "USE", "REFRESH", "REASSIGN", "OBJECT_REPLACEMENT",
            "OWNERSHIP_TRANSFER", "UNKNOWN_EFFECT",
        }:
            continue
        object_id = str(
            fact.get("object_id")
            or fact.get("abstract_object")
            or f"source::{subpath.source_identity}"
        )
        by_object[object_id].append(fact)

    chains: List[Dict[str, Any]] = []
    for object_id, events in by_object.items():
        events = sorted(events, key=_lifecycle_fact_order)
        for use_index, use in enumerate(events):
            if str(use.get("event_kind") or "").upper() != "USE":
                continue
            invalidation_index = next((
                index for index in range(use_index - 1, -1, -1)
                if str(events[index].get("event_kind") or "").upper() in {"RELEASE", "INVALIDATE"}
                and _branch_signatures_may_coexecute(
                    events[index].get("branch_signature"), use.get("branch_signature")
                )
            ), None)
            if invalidation_index is None:
                continue
            blockers = {"REFRESH", "REASSIGN", "OBJECT_REPLACEMENT"}
            if any(
                str(event.get("event_kind") or "").upper() in blockers
                for event in events[invalidation_index + 1:use_index]
            ):
                continue
            capture = next((
                event for event in reversed(events[:invalidation_index + 1])
                if str(event.get("event_kind") or "").upper() in {"ALIAS_CAPTURE", "OBJECT_REFERENCE"}
            ), None)
            chain = [item for item in (capture, events[invalidation_index], use) if item is not None]
            chains.append({"kind": "uaf", "object_id": object_id, "facts": chain})

        release_positions = [
            index for index, event in enumerate(events)
            if str(event.get("event_kind") or "").upper() in {"RELEASE", "RELEASE_AGAIN"}
        ]
        for position_index in range(1, len(release_positions)):
            first_index = release_positions[position_index - 1]
            second_index = release_positions[position_index]
            first, second = events[first_index], events[second_index]
            if not _branch_signatures_may_coexecute(
                first.get("branch_signature"), second.get("branch_signature")
            ):
                continue
            blockers = {"REFRESH", "REASSIGN", "OBJECT_REPLACEMENT"}
            if any(
                str(event.get("event_kind") or "").upper() in blockers
                for event in events[first_index + 1:second_index]
            ):
                continue
            chains.append({"kind": "double_free", "object_id": object_id, "facts": [first, second]})
    return chains








def _has_local_member_null_guard(code: str, member_expression: str, operation: str) -> bool:
    escaped = re.escape(member_expression).replace(r"\ ", r"\s*")
    operation_pos = code.find(operation)
    prefix = code[:operation_pos] if operation_pos >= 0 else code
    recent = prefix[-2000:]
    return bool(re.search(
        rf"\bif\s*\([^)]*(?:{escaped}\s*!=\s*(?:NULL|nullptr|0)|"
        rf"(?:NULL|nullptr|0)\s*!=\s*{escaped})[^)]*\)",
        recent,
        flags=re.S,
    ))


def _static_rescue_hypotheses(task: MultiSourcePathTask) -> List[Dict[str, Any]]:
    """Conservative parse-error rescue with source/object isolation and specific labels."""
    hypotheses: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    target_code = _target_function_code(task)
    code_null_guard_facts = _disjunctive_null_guard_facts(
        target_code, task.target_function
    ) if target_code else []

    def append_hypothesis(item: Dict[str, Any]) -> None:
        marker = json.dumps({
            "type": item.get("potential_vulnerability_type"),
            "cwe": item.get("cwe_id"),
            "root": _normalize_space(item.get("root_cause_hypothesis")).lower(),
            "subpaths": item.get("relevant_subpath_ids", []),
            "sinks": item.get("relevant_sink_ids", []),
        }, sort_keys=True, ensure_ascii=False)
        if marker in seen:
            return
        seen.add(marker)
        hypotheses.append(item)

    for subpath in task.source_subpaths:
        facts_text = "\n".join(
            f"{fact.get('event_kind')} {fact.get('code')}" for fact in subpath.facts
        ).lower()
        fact_ids = [fact["fact_id"] for fact in subpath.facts]
        sink_ids = [sink["sink_id"] for sink in subpath.sinks]
        lifecycle_kinds = {
            str(fact.get("event_kind", "")).upper()
            for fact in subpath.facts
        }
        sink_text = "\n".join(str(sink.get("operation", "")) for sink in subpath.sinks).lower()

        for semantic_fact in code_null_guard_facts:
            pointer_name = str(semantic_fact.get("nullable_pointer") or "the pointer")
            expression_match = re.search(
                rf"\b{re.escape(pointer_name)}\s*->\s*[A-Za-z_]\w*"
                r"(?:(?:\.|->)\s*[A-Za-z_]\w*)*",
                str(semantic_fact.get("code") or ""),
            )
            if expression_match is None:
                continue
            dereference_expression = re.sub(r"\s+", "", expression_match.group(0))
            expression_marker = re.sub(r"\W+", "", dereference_expression)
            related_sinks = [
                sink for sink in subpath.sinks
                if expression_marker and expression_marker in re.sub(
                    r"\W+", "", str(sink.get("operation") or "")
                )
            ]
            if not related_sinks:
                continue
            related_sink_ids = [sink["sink_id"] for sink in related_sinks]
            related_fact_ids = [
                fact["fact_id"] for fact in subpath.facts
                if expression_marker and expression_marker in re.sub(
                    r"\W+", "", str(fact.get("code") or "")
                )
            ]
            unsafe_disjuncts = _safe_list(semantic_fact.get("unsafe_disjuncts"))
            append_hypothesis({
                "potential_vulnerability_type": "Null Pointer Dereference",
                "cwe_id": "CWE-476",
                "root_cause_hypothesis": (
                    f"The condition guarding `{dereference_expression}` establishes "
                    f"`{pointer_name}` as non-NULL in only some top-level OR alternatives. "
                    "The listed operation can therefore dereference it when another "
                    f"alternative is true: {unsafe_disjuncts}."
                ),
                "suspected_broken_control": (
                    f"Non-null validation for `{pointer_name}` does not dominate the "
                    "dereference on every condition alternative."
                ),
                "required_preconditions": [
                    "One condition alternative that does not validate the pointer evaluates true.",
                    f"`{pointer_name}` is NULL on that path.",
                ],
                "security_boundary_assumption": "Unknown",
                "relevant_source_ids": [subpath.source_id],
                "relevant_subpath_ids": [subpath.subpath_id],
                "relevant_fact_ids": related_fact_ids,
                "relevant_sink_ids": related_sink_ids,
                "_static_rescue_kind": "disjunctive_null_guard",
            })

        # A missing NULL check is not itself evidence that a pointer-valued
        # member can be NULL. Keep this rescue only when the supplied context
        # contains an explicit nullable state for the exact member.
        pointer_read_arguments = {
            "strcpy": (1,), "strcat": (1,), "strlcpy": (1,), "strlen": (0,),
            "strcmp": (0, 1), "strncmp": (0, 1), "strchr": (0,), "strrchr": (0,),
        }
        nullable_evidence_context = "\n".join([
            target_code,
            task.code_context,
            subpath.source_origin,
            facts_text,
        ])
        for sink in subpath.sinks:
            operation = str(sink.get("operation") or "")
            for api_name, positions in pointer_read_arguments.items():
                arguments = _call_arguments(operation, api_name)
                if not arguments:
                    continue
                for position in positions:
                    if position >= len(arguments):
                        continue
                    member_match = re.search(
                        r"\b([A-Za-z_]\w*\s*->\s*[A-Za-z_]\w*)\b",
                        arguments[position],
                    )
                    if member_match is None:
                        continue
                    member_expression = re.sub(r"\s+", "", member_match.group(1))
                    if _has_local_member_null_guard(target_code, member_expression, operation):
                        continue
                    escaped_member = re.escape(member_expression).replace(
                        r"\->", r"\s*->\s*"
                    )
                    has_explicit_nullable_state = bool(re.search(
                        rf"{escaped_member}\s*=\s*(?:NULL|nullptr|0)\b",
                        nullable_evidence_context,
                    ))
                    if not has_explicit_nullable_state:
                        continue
                    append_hypothesis({
                        "potential_vulnerability_type": "Null Pointer Dereference",
                        "cwe_id": "CWE-476",
                        "root_cause_hypothesis": (
                            f"Pointer-valued member `{member_expression}` has an explicit NULL "
                            f"state in the supplied evidence and reaches `{api_name}` without a "
                            "dominating member-level NULL check."
                        ),
                        "suspected_broken_control": (
                            f"Missing member-level NULL validation for `{member_expression}` before "
                            f"the `{api_name}` read."
                        ),
                        "required_preconditions": [
                            f"The explicit NULL state of `{member_expression}` reaches this call.",
                            f"Execution reaches `{api_name}` without a dominating NULL guard.",
                        ],
                        "security_boundary_assumption": "Unknown",
                        "relevant_source_ids": [subpath.source_id],
                        "relevant_subpath_ids": [subpath.subpath_id],
                        "relevant_fact_ids": fact_ids,
                        "relevant_sink_ids": [sink["sink_id"]],
                        "_static_rescue_kind": "explicit_nullable_member_api_argument",
                    })

        for chain in _ordered_lifecycle_evidence(subpath):
            chain_facts = chain["facts"]
            chain_fact_ids = _dedup_preserve_order(
                fact.get("fact_id") for fact in chain_facts if fact.get("fact_id")
            )
            object_id = chain["object_id"]
            related_sink_ids = _dedup_preserve_order(
                sink_id
                for fact in chain_facts
                for sink_id in _safe_list(fact.get("supported_sink_ids"))
            ) or sink_ids
            if chain["kind"] == "uaf":
                append_hypothesis({
                    "potential_vulnerability_type": "Use-After-Free",
                    "cwe_id": "CWE-416",
                    "root_cause_hypothesis": (
                        f"{subpath.subpath_id} has an ordered same-object lifecycle chain for {object_id}: "
                        "alias/reference capture -> release or backing-storage invalidation -> stale use, "
                        "with no intervening refresh or object replacement in the supplied path evidence."
                    ),
                    "relevant_source_ids": [subpath.source_id],
                    "relevant_subpath_ids": [subpath.subpath_id],
                    "relevant_fact_ids": chain_fact_ids,
                    "relevant_sink_ids": related_sink_ids,
                    "_lifecycle_object_id": object_id,
                })
            else:
                append_hypothesis({
                    "potential_vulnerability_type": "Double Free",
                    "cwe_id": "CWE-415",
                    "root_cause_hypothesis": (
                        f"{subpath.subpath_id} has two ordered, branch-compatible releases of the "
                        f"same abstract object {object_id}, with no intervening object replacement."
                    ),
                    "relevant_source_ids": [subpath.source_id],
                    "relevant_subpath_ids": [subpath.subpath_id],
                    "relevant_fact_ids": chain_fact_ids,
                    "relevant_sink_ids": related_sink_ids,
                    "_lifecycle_object_id": object_id,
                })

        if "integer arithmetic" in facts_text and (
            "integer control use" in facts_text
            or any(token in facts_text for token in (
                "array index", "memcpy", "memmove", "malloc", "calloc", "pointer"
            ))
        ):
            append_hypothesis({
                "potential_vulnerability_type": "Integer Overflow or Wraparound",
                "cwe_id": "CWE-190",
                "root_cause_hypothesis": (
                    f"{subpath.subpath_id} contains an integer update followed by a control-flow or "
                    "memory-sensitive use; type bounds and guards require second-pass verification."
                ),
                "relevant_source_ids": [subpath.source_id],
                "relevant_subpath_ids": [subpath.subpath_id],
                "relevant_fact_ids": fact_ids,
                "relevant_sink_ids": sink_ids,
            })

        # Kernel user-copy helpers must not write more bytes than the caller
        # requested, even when the destination address range itself is accessible.
        # Preserve that length relation as an explicit candidate when it is visible.
        signature_text = "\n".join(target_code.splitlines()[:8])
        extent_parameters = _dedup_preserve_order(re.findall(
            r"\b(?:size_t|ssize_t|int|unsigned(?:\s+\w+)?)\s*\*\s*"
            r"([A-Za-z_]\w*(?:len|size|count)[A-Za-z_0-9]*)\b",
            signature_text,
            flags=re.I,
        ))
        for sink in subpath.sinks:
            operation = str(sink.get("operation") or "")
            api_name = next(
                (name for name in ("__copy_to_user", "copy_to_user")
                if re.search(rf"\b{re.escape(name)}\s*\(", operation)),
                None,
            )
            if not api_name:
                continue
            arguments = _call_arguments(operation, api_name)
            if len(arguments) < 3:
                continue
            destination, copy_length = arguments[0], arguments[2]
            for extent_name in extent_parameters:
                escaped_length = re.escape(_normalize_space(copy_length)).replace(
                    r"\ ", r"\s*"
                )
                escaped_extent = re.escape(extent_name)
                relation_pattern = (
                    rf"(?:{escaped_length}\s*<=\s*\*\s*{escaped_extent}|"
                    rf"\*\s*{escaped_extent}\s*>=\s*{escaped_length}|"
                    rf"\bmin(?:_t)?\s*\([^;]*\*\s*{escaped_extent}[^;]*\))"
                )
                before_call = target_code.split(operation, 1)[0]
                if re.search(relation_pattern, before_call, flags=re.S):
                    continue
                append_hypothesis({
                    "potential_vulnerability_type": "Buffer Overflow",
                    "cwe_id": "CWE-119",
                    "root_cause_hypothesis": (
                        f"`{api_name}` copies `{copy_length}` bytes to `{destination}`, but "
                        f"the supplied path does not establish `{copy_length} <= *{extent_name}`, "
                        "the caller-provided destination extent."
                    ),
                    "suspected_broken_control": (
                        f"The copy length is not bounded by `*{extent_name}` before the user copy."
                    ),
                    "required_preconditions": [
                        f"`{copy_length}` exceeds the requested extent `*{extent_name}`.",
                        "Execution reaches the user-copy operation.",
                    ],
                    "security_boundary_assumption": "Caller controls the destination and requested extent.",
                    "relevant_source_ids": [subpath.source_id],
                    "relevant_subpath_ids": [subpath.subpath_id],
                    "relevant_fact_ids": fact_ids,
                    "relevant_sink_ids": [sink["sink_id"]],
                    "_static_rescue_kind": "user_copy_extent_mismatch",
                })

        # Specific write-side rescue. This is deliberately distinct from OOB read.
        if subpath.source_status == "precise" and any(token in sink_text for token in (
            "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "snprintf", "vsprintf"
        )):
            append_hypothesis({
                "potential_vulnerability_type": "Buffer Overflow",
                "cwe_id": "CWE-120",
                "root_cause_hypothesis": (
                    f"A precisely tracked source in {subpath.subpath_id} reaches a copy or string/format "
                    "write. The verifier must compare the requested write length with the concrete "
                    "destination capacity and confirm whether the dominating checks are sufficient."
                ),
                "relevant_source_ids": [subpath.source_id],
                "relevant_subpath_ids": [subpath.subpath_id],
                "relevant_fact_ids": fact_ids,
                "relevant_sink_ids": sink_ids,
            })

        if subpath.source_status == "precise" and any(token in sink_text for token in (
            "strlen", "strnlen", "memcmp", "strcmp", "strncmp"
        )):
            append_hypothesis({
                "potential_vulnerability_type": "Out-of-Bounds Read",
                "cwe_id": "CWE-125",
                "root_cause_hypothesis": (
                    f"A precisely tracked source in {subpath.subpath_id} reaches a scan/comparison read; "
                    "the verifier must prove termination or readable extent."
                ),
                "relevant_source_ids": [subpath.source_id],
                "relevant_subpath_ids": [subpath.subpath_id],
                "relevant_fact_ids": fact_ids,
                "relevant_sink_ids": sink_ids,
            })

    # Keep narrowly identifiable bounds hazards visible even when broad tasks
    # cause the first-stage model to overlook one concrete operation. These
    # candidates carry exact evidence IDs and remain subject to verification.
    bounded_rescue_operations: Set[Tuple[str, str]] = set()
    for subpath in task.source_subpaths:
        fact_ids = [
            fact["fact_id"] for fact in subpath.facts if fact.get("fact_id")
        ]
        for sink in subpath.sinks:
            operation = str(sink.get("operation") or "")
            sink_id = sink.get("sink_id")
            if not sink_id:
                continue
            supporting_fact_ids = [
                fact["fact_id"]
                for fact in subpath.facts
                if fact.get("fact_id")
                and (
                    sink_id in _safe_list(fact.get("supported_sink_ids"))
                    or _normalize_code(fact.get("code")) == _normalize_code(operation)
                )
            ] or fact_ids

            literal_index = re.search(
                r"\(\([^(){};]*\[\]\)\s*\{([^{}]*)\}\s*\)\s*"
                r"\[\s*([^\]]+)\s*\]",
                operation,
                flags=re.S,
            )
            if literal_index is not None:
                elements = [
                    element
                    for element in _split_call_arguments(literal_index.group(1))
                    if element
                ]
                index_expression = _normalize_space(literal_index.group(2))
                controls_text = " ".join(
                    _normalize_space(control)
                    for control in _safe_list(sink.get("controls"))
                )
                limit = len(elements)
                escaped_index = re.escape(index_expression).replace(r"\ ", r"\s*")
                has_upper_bound = bool(limit and re.search(
                    rf"(?:{escaped_index}\s*<\s*{limit}\b|"
                    rf"{escaped_index}\s*<=\s*{limit - 1}\b|"
                    rf"!\s*\(\s*{escaped_index}\s*>=\s*{limit}\b)",
                    controls_text,
                ))
                rescue_marker = (
                    "finite_table_dynamic_index",
                    str(sink.get("operation_id") or _normalize_code(operation)),
                )
                if (
                    limit
                    and not has_upper_bound
                    and rescue_marker not in bounded_rescue_operations
                ):
                    bounded_rescue_operations.add(rescue_marker)
                    append_hypothesis({
                        "potential_vulnerability_type": "Out-of-Bounds Read",
                        "cwe_id": "CWE-125",
                        "root_cause_hypothesis": (
                            f"The dynamic index '{index_expression}' selects from an inline "
                            f"table with {limit} elements at {sink.get('operation_id')}. The "
                            "recorded path conditions do not establish the required upper bound."
                        ),
                        "suspected_broken_control": (
                            f"No dominating '{index_expression} < {limit}' condition is "
                            "present in the extracted path evidence."
                        ),
                        "required_preconditions": [
                            f"'{index_expression}' can be at least {limit}.",
                            "Execution reaches the indexed table access.",
                        ],
                        "security_boundary_assumption": "Unknown",
                        "relevant_source_ids": [subpath.source_id],
                        "relevant_subpath_ids": [subpath.subpath_id],
                        "relevant_fact_ids": supporting_fact_ids,
                        "relevant_sink_ids": [sink_id],
                        "_static_rescue_kind": "finite_table_dynamic_index",
                    })

            cursor_update = re.search(
                r"\b([A-Za-z_]\w*)\s*-=\s*[^;]*\b\1\s*"
                r"\[\s*-\s*\d+\s*\]",
                operation,
                flags=re.S,
            )
            cursor_marker = (
                "self_relative_cursor_underflow",
                str(sink.get("operation_id") or _normalize_code(operation)),
            )
            if (
                cursor_update is not None
                and subpath.source_status == "precise"
                and cursor_marker not in bounded_rescue_operations
            ):
                bounded_rescue_operations.add(cursor_marker)
                cursor_name = cursor_update.group(1)
                append_hypothesis({
                    "potential_vulnerability_type": "Stack or Pointer Underflow",
                    "cwe_id": "CWE-124",
                    "root_cause_hypothesis": (
                        f"Operation {sink.get('operation_id')} derives a decrement from a "
                        f"negative-offset read of '{cursor_name}' and then moves the same "
                        "cursor backward. Verification must establish both lower bounds."
                    ),
                    "suspected_broken_control": (
                        f"The extracted controls do not directly establish the lower bound "
                        f"of '{cursor_name}' for this variable decrement."
                    ),
                    "required_preconditions": [
                        "The encoded decrement exceeds the available preceding elements.",
                        "The resulting pointer or negative-offset operand is used.",
                    ],
                    "security_boundary_assumption": "Unknown",
                    "relevant_source_ids": [subpath.source_id],
                    "relevant_subpath_ids": [subpath.subpath_id],
                    "relevant_fact_ids": supporting_fact_ids,
                    "relevant_sink_ids": [sink_id],
                    "_static_rescue_kind": "self_relative_cursor_underflow",
                })

        for fact in subpath.facts:
            if str(fact.get("event_kind") or "").upper() != "UNCOVERED_HIGH_RISK_OPERATION":
                continue
            operation = str(fact.get("code") or "")
            indexed_write = re.search(
                r"\b([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*"
                r"\[\s*([A-Za-z_]\w*)\s*\]\s*=",
                operation,
            )
            if indexed_write is None or not target_code:
                continue
            index_name = indexed_write.group(2)
            normalized_code = _normalize_space(target_code)
            operation_match = re.search(
                re.escape(_normalize_space(operation)), normalized_code
            )
            if operation_match is None:
                continue
            tail = normalized_code[operation_match.end():operation_match.end() + 1200]
            advances_index = re.search(
                rf"\b{re.escape(index_name)}\s*(?:\+\+|\+=\s*1)",
                tail,
            )
            late_check = re.search(
                rf"\bif\s*\([^)]*\b{re.escape(index_name)}\b[^)]*\)",
                tail,
            )
            if (
                advances_index is None
                or late_check is None
                or advances_index.start() > late_check.start()
            ):
                continue
            append_hypothesis({
                "potential_vulnerability_type": "Out-of-Bounds Write",
                "cwe_id": "CWE-787",
                "root_cause_hypothesis": (
                    f"The uncovered operation '{_normalize_space(operation)}' writes "
                    f"through index '{index_name}', advances it, and only later checks "
                    "the resulting count. Verification must establish a pre-write bound."
                ),
                "suspected_broken_control": (
                    f"The visible count check involving '{index_name}' occurs after "
                    "the indexed write."
                ),
                "required_preconditions": [
                    f"'{index_name}' can reach the destination capacity before the write.",
                    "No equivalent dominating capacity check is present on the same path.",
                ],
                "security_boundary_assumption": "Unknown",
                "relevant_source_ids": [subpath.source_id],
                "relevant_subpath_ids": [subpath.subpath_id],
                "relevant_fact_ids": (
                    [fact["fact_id"]] if fact.get("fact_id") else fact_ids
                ),
                "relevant_sink_ids": [
                    sink["sink_id"] for sink in subpath.sinks if sink.get("sink_id")
                ],
                "_static_rescue_kind": "post_write_count_validation",
            })

    # Detect a narrow state-mediated lifetime pattern without creating another
    # LLM task: a membership flag is checked and cleared before the lock that
    # protects a destructive container mutation.
    target_code = _target_function_code(task)

    destructive_entries: List[Tuple[SourceSubpath, Dict[str, Any]]] = []
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            if re.search(
                r"\b(?:list_del(?:_rcu|_init)?|hlist_del(?:_rcu|_init)?|rb_erase)\s*\(",
                str(sink.get("operation") or ""),
                flags=re.I,
            ):
                destructive_entries.append((subpath, sink))

    for subpath, sink in destructive_entries:
        for control in _safe_list(sink.get("controls")):
            state_match = re.fullmatch(
                r"\(?\s*([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)+)\s*\)?",
                str(control).strip(),
            )
            if state_match is None or not target_code:
                continue
            state_expr = state_match.group(1)
            escaped_state = re.escape(state_expr)
            guard_match = re.search(
                rf"\bif\s*\(\s*{escaped_state}\s*\)",
                target_code,
            )
            clear_match = re.search(
                rf"\b{escaped_state}\s*=\s*(?:false|0|NULL|nullptr)\s*;",
                target_code,
            )
            lock_match = re.search(
                r"\b(?:spin|raw_spin|mutex|rwlock)_lock(?:_irq|_irqsave|_bh)?\s*\(",
                target_code,
            )
            operation_match = re.search(
                re.escape(str(sink.get("operation") or "").strip()),
                target_code,
            )
            if not all((guard_match, clear_match, lock_match, operation_match)):
                continue
            if not (
                guard_match.start() < clear_match.start()
                < lock_match.start() < operation_match.start()
            ):
                continue

            related = [
                (candidate_subpath, candidate_sink)
                for candidate_subpath, candidate_sink in destructive_entries
                if _normalize_code(candidate_sink.get("operation"))
                == _normalize_code(sink.get("operation"))
            ]
            append_hypothesis({
                "potential_vulnerability_type": "Race-Induced List Corruption / Use-After-Free",
                "cwe_id": "CWE-416",
                "root_cause_hypothesis": (
                    f"The membership state '{state_expr}' is checked and cleared before the "
                    f"lock that serializes '{sink.get('operation')}'. Two executions on the "
                    "same object can therefore both pass the predicate before either clears "
                    "it and then perform the destructive removal twice, corrupting the "
                    "container state and enabling invalid later access."
                ),
                "suspected_broken_control": (
                    f"The lock does not cover the complete '{state_expr}' check, update, "
                    "and destructive-removal sequence."
                ),
                "required_preconditions": [
                    "Two executions can operate concurrently on the same object.",
                    f"'{state_expr}' is true before both predicate reads.",
                ],
                "security_boundary_assumption": "Unknown",
                "relevant_source_ids": _dedup_preserve_order(
                    candidate_subpath.source_id for candidate_subpath, _ in related
                ),
                "relevant_subpath_ids": _dedup_preserve_order(
                    candidate_subpath.subpath_id for candidate_subpath, _ in related
                ),
                "relevant_fact_ids": _dedup_preserve_order(
                    fact["fact_id"]
                    for candidate_subpath, _ in related
                    for fact in candidate_subpath.facts
                    if fact.get("fact_id")
                ),
                "relevant_sink_ids": _dedup_preserve_order(
                    candidate_sink["sink_id"]
                    for _, candidate_sink in related
                    if candidate_sink.get("sink_id")
                ),
                "_static_rescue_kind": "check_then_act_container",
            })
            break

    all_source_ids = _dedup_preserve_order(
        subpath.source_id for subpath in task.source_subpaths
    )
    all_subpath_ids = _dedup_preserve_order(
        subpath.subpath_id for subpath in task.source_subpaths
    )
    all_fact_ids = _dedup_preserve_order(
        fact["fact_id"]
        for subpath in task.source_subpaths
        for fact in subpath.facts
        if fact.get("fact_id")
    )
    all_sink_ids = _dedup_preserve_order(
        sink["sink_id"]
        for subpath in task.source_subpaths
        for sink in subpath.sinks
        if sink.get("sink_id")
    )
    has_precise_source = any(
        str(subpath.source_status or "").lower() == "precise"
        for subpath in task.source_subpaths
    )

    # A void validation helper can silently suppress an error while its caller
    # continues with unchanged output state. Preserve this as an inter-procedural
    # control gap rather than treating the helper-local return as caller-level safety.
    if has_precise_source and target_code and re.search(
        rf"\bvoid\s+{re.escape(task.target_function)}\s*\(",
        target_code,
    ):
        error_return = re.search(
            r"\bif\s*\(\s*(?:IS_ERR|IS_ERR_OR_NULL)\s*\(\s*([A-Za-z_]\w*)\s*\)"
            r"\s*\)\s*(?:\{\s*)?return\s*;",
            target_code,
            flags=re.S,
        )
        output_parameters = _dedup_preserve_order(re.findall(
            r"\*\s*([A-Za-z_]\w*)\s*(?:\|=|&=|\^=|\+=|-=|=)",
            target_code,
        ))
        policy_tokens = _dedup_preserve_order(re.findall(
            r"\*\s*[A-Za-z_]\w*\s*(?:\|=|&=|\^=|=)\s*"
            r"([A-Z_][A-Z0-9_]{3,})",
            target_code,
        ))
        call_matches = list(re.finditer(
            rf"\b{re.escape(task.target_function)}\s*\((.*?)\)\s*;",
            task.code_context,
            flags=re.S,
        ))
        caller_continues = False
        output_actuals: List[str] = []
        for call_match in call_matches:
            actuals = _dedup_preserve_order(re.findall(
                r"&\s*([A-Za-z_]\w*)",
                call_match.group(1),
            ))
            tail = task.code_context[call_match.end():call_match.end() + 2500]
            used_after = [
                actual for actual in actuals
                if re.search(rf"\b{re.escape(actual)}\b", tail)
            ]
            if used_after:
                output_actuals.extend(used_after)
                caller_continues = True
        if error_return and output_parameters and caller_continues and all_sink_ids:
            append_hypothesis({
                "potential_vulnerability_type": "Unpropagated Validation Failure / Unsafe Downstream Selection",
                "cwe_id": "N/A",
                "root_cause_hypothesis": (
                    f"The void helper '{task.target_function}' returns when "
                    f"{error_return.group(1)} is error-encoded, but cannot propagate either "
                    "that failure or the validation result to its caller. The caller then "
                    f"continues with output state {sorted(set(output_actuals))}; verify "
                    "whether unchanged/default flags weaken the required policy "
                    f"{policy_tokens or '[not explicitly named]'} or permit an incompatible "
                    "downstream object selection."
                ),
                "suspected_broken_control": (
                    "A helper-local validation failure is not converted into a caller-level "
                    "failure or an explicit validity result. "
                    + (
                        f"The helper encodes policy {policy_tokens} only through its "
                        "output flags, so the caller cannot distinguish failed or "
                        "incompatible validation from a deliberately broad/default filter."
                        if policy_tokens else ""
                    )
                ),
                "required_preconditions": [
                    f"{error_return.group(1)} can be error-encoded or fail the required policy.",
                    "The unchanged output state broadens or weakens downstream selection.",
                    "The selected downstream object can violate the expected memory-safety invariant.",
                ],
                "security_boundary_assumption": "Unknown",
                "relevant_source_ids": all_source_ids,
                "relevant_subpath_ids": all_subpath_ids,
                "relevant_fact_ids": all_fact_ids,
                "relevant_sink_ids": all_sink_ids,
                "_static_rescue_kind": "unpropagated_error_state",
            })

    # Track the common size-query -> allocation -> external fill pattern. A zero
    # size is not itself a vulnerability, but omitting a positive-size guard can
    # leave only a header allocation for a later payload write.
    if has_precise_source and target_code and all_sink_ids:
        scalar_names: Set[str] = set()
        for declaration in re.finditer(
            r"\b(?:size_t|ssize_t|ptrdiff_t|u?int(?:8|16|32|64)_t|"
            r"unsigned(?:\s+(?:char|short|int|long))?|signed(?:\s+(?:char|short|int|long))?|"
            r"char|short|int|long)\s+([^;]+);",
            target_code,
        ):
            for declarator in declaration.group(1).split(","):
                name_match = re.search(r"\b([A-Za-z_]\w*)\b", declarator)
                if name_match:
                    scalar_names.add(name_match.group(1))
        out_size_names = _dedup_preserve_order(
            match.group(1)
            for match in re.finditer(
                r"\b[A-Za-z_]\w*\s*\([^;]*&\s*([A-Za-z_]\w*)[^;]*\)\s*;",
                target_code,
                flags=re.S,
            )
            if match.group(1) in scalar_names
            and re.search(
                r"(?:size|len|count|num|capacity|bytes|width|height)",
                match.group(1),
                flags=re.I,
            )
        )
        for size_name in out_size_names:
            allocation = re.search(
                rf"\b([A-Za-z_]\w*)\s*=\s*"
                rf"(?:g_malloc|malloc|calloc|realloc|kmalloc|kzalloc|OPENSSL_malloc)"
                rf"\s*\([^;]*\b{re.escape(size_name)}\b[^;]*\)\s*;",
                target_code,
                flags=re.S,
            )
            if allocation is None:
                continue
            allocated_name = allocation.group(1)
            after_allocation = target_code[allocation.end():]
            fill = re.search(
                rf"\b([A-Za-z_]\w*(?:fill|write|copy|read|recv)[A-Za-z_0-9]*)\s*"
                rf"\([^;]*(?:\b{re.escape(allocated_name)}\b|"
                rf"\b{re.escape(allocated_name)}\s*(?:->|\.))[^;]*\)\s*;",
                after_allocation,
                flags=re.I | re.S,
            )
            positive_guard = re.search(
                rf"\bif\s*\([^)]*(?:!\s*{re.escape(size_name)}\b|"
                rf"\b{re.escape(size_name)}\s*(?:==|<=)\s*0\b|"
                rf"\b{re.escape(size_name)}\s*>\s*0\b)",
                target_code[:allocation.start()],
            )
            if fill is None or positive_guard is not None:
                continue
            append_hypothesis({
                "potential_vulnerability_type": "Zero-Size Allocation Followed by External Buffer Access",
                "cwe_id": "N/A",
                "root_cause_hypothesis": (
                    f"External output '{size_name}' determines the allocation of "
                    f"'{allocated_name}', which is then passed to '{fill.group(1)}' without "
                    "a preceding positive-size check. Verify the callee's zero-size behavior "
                    "and whether it can access payload storage beyond the allocated extent."
                ),
                "suspected_broken_control": (
                    f"No explicit zero-boundary validation for '{size_name}' is present "
                    "between the size query and the external buffer operation."
                ),
                "required_preconditions": [
                    f"The size provider can return {size_name} == 0.",
                    f"{fill.group(1)} accesses payload storage when the size is zero.",
                ],
                "security_boundary_assumption": "Unknown",
                "relevant_source_ids": all_source_ids,
                "relevant_subpath_ids": all_subpath_ids,
                "relevant_fact_ids": all_fact_ids,
                "relevant_sink_ids": all_sink_ids,
                "_static_rescue_kind": "zero_size_external_fill",
            })
            break

    # If a grow/resize operation and a later sibling pointer use are visible but
    # their alias relation is absent, retain the relocation hazard as an explicit
    # proof-bearing hypothesis. Verification must establish the derivation relation;
    # matching field names alone are never sufficient for confirmation.
    if has_precise_source and target_code and all_sink_ids:
        growth_match = re.search(
            r"\b([A-Za-z_]\w*(?:grow|resize|realloc|expand|reserve)[A-Za-z_0-9]*)"
            r"\s*\(\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)",
            target_code,
            flags=re.I,
        )
        if growth_match:
            growth_func, owner_name, backing_field = growth_match.groups()
            after_growth = target_code[growth_match.end():]
            sibling_uses = _dedup_preserve_order(
                match.group(1)
                for match in re.finditer(
                    rf"\b{re.escape(owner_name)}\s*->\s*([A-Za-z_]\w*)",
                    after_growth,
                )
                if match.group(1) != backing_field
                and re.search(
                    r"(?:msg|ptr|data|cursor|current|start|base|content)",
                    match.group(1),
                    flags=re.I,
                )
            )
            for sibling_field in sibling_uses:
                sibling_expr = f"{owner_name}->{sibling_field}"
                refreshed = re.search(
                    rf"\b{re.escape(owner_name)}\s*->\s*{re.escape(sibling_field)}\s*=",
                    after_growth,
                )
                consumed = re.search(
                    rf"\b[A-Za-z_]\w*\s*\([^;]*\b{re.escape(owner_name)}\s*->\s*"
                    rf"{re.escape(sibling_field)}\b[^;]*\)",
                    after_growth,
                    flags=re.S,
                )
                if refreshed is not None or consumed is None:
                    continue
                append_hypothesis({
                    "potential_vulnerability_type": "Potential Stale Pointer After Backing-Storage Relocation",
                    "cwe_id": "CWE-416",
                    "root_cause_hypothesis": (
                        f"'{growth_func}' may relocate '{owner_name}->{backing_field}', after "
                        f"which '{sibling_expr}' is consumed without an observed refresh. "
                        f"Confirm whether '{sibling_expr}' is a derived pointer into that "
                        "backing storage; if so, the later use is stale after relocation."
                    ),
                    "suspected_broken_control": (
                        "No pointer refresh is visible between backing-storage growth and "
                        "the later sibling-pointer use."
                    ),
                    "required_preconditions": [
                        f"'{sibling_expr}' aliases storage owned by "
                        f"'{owner_name}->{backing_field}'.",
                        f"'{growth_func}' can relocate that storage.",
                    ],
                    "security_boundary_assumption": "Unknown",
                    "relevant_source_ids": all_source_ids,
                    "relevant_subpath_ids": all_subpath_ids,
                    "relevant_fact_ids": all_fact_ids,
                    "relevant_sink_ids": all_sink_ids,
                    "_static_rescue_kind": "backing_relocation_proof_gap",
                })
                break

    # Preserve teardown-then-cleanup chains that cross an external API and a
    # local helper. The hypothesis remains conditional on the exact teardown
    # contract, but the chain must not disappear merely because the first effect
    # is implemented outside the current source file.
    if has_precise_source and target_code and all_sink_ids:
        teardown_matches = list(re.finditer(
            r"\b([A-Za-z_]\w*(?:end|complete|destroy|release|put|free|unmap)"
            r"[A-Za-z_0-9]*)\s*\(\s*"
            r"([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)",
            target_code,
            flags=re.I,
        ))
        for teardown in teardown_matches:
            teardown_name, owner_name, field_name = teardown.groups()
            tail = target_code[teardown.end():]
            cleanup_call = re.search(
                rf"\b([A-Za-z_]\w*(?:finish|cleanup|remove|release|destroy|free)"
                rf"[A-Za-z_0-9]*)\s*\(\s*{re.escape(owner_name)}\s*\)\s*;",
                tail,
                flags=re.I,
            )
            if cleanup_call is None:
                continue
            before_cleanup = tail[:cleanup_call.start()]
            if re.search(
                rf"\b{re.escape(owner_name)}\s*->\s*{re.escape(field_name)}\s*="
                r"\s*(?:NULL|nullptr|0)\s*;",
                before_cleanup,
            ):
                continue
            cleanup_name = cleanup_call.group(1)
            header = re.search(
                rf"// [^\n]*Function: {re.escape(cleanup_name)}\n",
                task.code_context,
            )
            if header is None:
                continue
            cleanup_start = header.end()
            next_header = re.search(
                r"\n// [^\n]*Function: ",
                task.code_context[cleanup_start:],
            )
            cleanup_end = (
                cleanup_start + next_header.start()
                if next_header is not None
                else len(task.code_context)
            )
            cleanup_code = task.code_context[cleanup_start:cleanup_end]
            field_cleanup = re.search(
                rf"\b(?:kfree|free|[A-Za-z_]\w*put[A-Za-z_0-9]*)\s*"
                rf"\([^;]*->\s*{re.escape(field_name)}\b[^;]*\)",
                cleanup_code,
                flags=re.I | re.S,
            )
            if field_cleanup is None:
                continue
            append_hypothesis({
                "potential_vulnerability_type": "Potential Double Release Across Teardown and Cleanup",
                "cwe_id": "CWE-415",
                "root_cause_hypothesis": (
                    f"'{teardown_name}' is invoked on "
                    f"'{owner_name}->{field_name}', after which "
                    f"'{cleanup_name}({owner_name})' releases the same field through "
                    f"'{_normalize_space(field_cleanup.group(0))}' without an intervening "
                    "NULL/reset assignment. Verify the exact teardown API contract; if it "
                    "invalidates or releases the request-owned resource, the cleanup path "
                    "performs a second release."
                ),
                "suspected_broken_control": (
                    f"'{owner_name}->{field_name}' remains non-NULL across external "
                    "teardown and local cleanup."
                ),
                "required_preconditions": [
                    f"'{teardown_name}' invalidates or releases the resource represented "
                    f"by '{owner_name}->{field_name}'.",
                    f"'{cleanup_name}' executes on the same owner instance.",
                ],
                "security_boundary_assumption": "Unknown",
                "relevant_source_ids": all_source_ids,
                "relevant_subpath_ids": all_subpath_ids,
                "relevant_fact_ids": all_fact_ids,
                "relevant_sink_ids": all_sink_ids,
                "_static_rescue_kind": "external_teardown_cleanup",
            })
            break

    # Joint rescue is limited to sources that actually reach the same concrete OPx.
    operation_entries: Dict[str, List[Tuple[SourceSubpath, Dict[str, Any]]]] = defaultdict(list)
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            operation_entries[str(sink.get("operation_id", ""))].append((subpath, sink))
    for operation_id, entries in operation_entries.items():
        unique_sources = _dedup_preserve_order(subpath.source_id for subpath, _ in entries)
        if len(unique_sources) < 2:
            continue
        operation_text = " ".join(
            str(sink.get("operation", "")).lower() for _, sink in entries
        )
        involved_subpaths = _dedup_preserve_order(subpath.subpath_id for subpath, _ in entries)
        common = {
            "relevant_source_ids": unique_sources,
            "relevant_subpath_ids": involved_subpaths,
            "relevant_fact_ids": _dedup_preserve_order(
                fact["fact_id"] for subpath, _ in entries for fact in subpath.facts
            ),
            "relevant_sink_ids": _dedup_preserve_order(sink["sink_id"] for _, sink in entries),
        }
        if any(token in operation_text for token in (
            "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "snprintf", "vsprintf"
        )):
            append_hypothesis({
                "potential_vulnerability_type": "Buffer Overflow",
                "cwe_id": "CWE-120",
                "root_cause_hypothesis": (
                    f"Multiple independently tracked sources reach copy/write operation {operation_id}. "
                    "The verifier must relate destination capacity, write length, source extent, and "
                    "their dominating checks to determine whether the destination can overflow."
                ),
                **common,
            })
            # A copy may separately over-read its source; keep this as a distinct root cause.
            if any(token in operation_text for token in ("memcpy", "memmove", "strncpy")):
                append_hypothesis({
                    "potential_vulnerability_type": "Out-of-Bounds Read",
                    "cwe_id": "CWE-125",
                    "root_cause_hypothesis": (
                        f"Multiple sources reach copy operation {operation_id}; the requested length may "
                        "exceed the readable extent of the source object independently of destination capacity."
                    ),
                    **common,
                })
        elif "[" in operation_text:
            append_hypothesis({
                "potential_vulnerability_type": "Out-of-Bounds Access",
                "cwe_id": "N/A",
                "root_cause_hypothesis": (
                    f"Multiple independently tracked sources reach indexed operation {operation_id}; "
                    "the verifier must relate the index/range to the referenced object's bounds."
                ),
                **common,
            })

    for index, item in enumerate(hypotheses, start=1):
        item["hypothesis_id"] = f"H{index}"
        item["_preverify_fingerprint"] = _hypothesis_causal_fingerprint(task, item, include_path=True)
        item["_root_cause_fingerprint"] = _hypothesis_causal_fingerprint(task, item, include_path=False)
    return hypotheses


def _merge_additive_static_hypotheses(
    task: MultiSourcePathTask,
    model_hypotheses: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    """Retain precise lifecycle chains and narrowly scoped semantic rescues."""
    merged = [dict(item) for item in model_hypotheses]
    by_fingerprint: Dict[str, Dict[str, Any]] = {}
    for item in merged:
        fingerprint = str(
            item.get("_root_cause_fingerprint")
            or _hypothesis_causal_fingerprint(task, item, include_path=False)
        )
        item["_root_cause_fingerprint"] = fingerprint
        item["_preverify_fingerprint"] = str(
            item.get("_preverify_fingerprint")
            or _hypothesis_causal_fingerprint(task, item, include_path=True)
        )
        by_fingerprint[fingerprint] = item

    additive_kinds = {
        "check_then_act_container",
        "disjunctive_null_guard",
        "explicit_nullable_member_api_argument",
        "unpropagated_error_state",
        "zero_size_external_fill",
        "backing_relocation_proof_gap",
        "external_teardown_cleanup",
        "finite_table_dynamic_index",
        "self_relative_cursor_underflow",
        "post_write_count_validation",
        "user_copy_extent_mismatch",
    }
    added = 0
    for rescue in _static_rescue_hypotheses(task):
        is_precise_lifecycle = (
            _meaningful_label(rescue.get("cwe_id")) in {"CWE-415", "CWE-416"}
            and bool(rescue.get("_lifecycle_object_id"))
        )
        if not is_precise_lifecycle and rescue.get("_static_rescue_kind") not in additive_kinds:
            continue
        fingerprint = str(
            rescue.get("_root_cause_fingerprint")
            or _hypothesis_causal_fingerprint(task, rescue, include_path=False)
        )
        existing = by_fingerprint.get(fingerprint)
        if existing is not None:
            for field_name in (
                "relevant_source_ids", "relevant_subpath_ids",
                "relevant_fact_ids", "relevant_sink_ids",
            ):
                existing[field_name] = _dedup_preserve_order(
                    _safe_list(existing.get(field_name)) + _safe_list(rescue.get(field_name))
                )
            continue
        rescue = dict(rescue)
        rescue["_root_cause_fingerprint"] = fingerprint
        rescue["_preverify_fingerprint"] = _hypothesis_causal_fingerprint(
            task, rescue, include_path=True
        )
        merged.append(rescue)
        by_fingerprint[fingerprint] = rescue
        added += 1

    for index, item in enumerate(merged, start=1):
        item["hypothesis_id"] = f"H{index}"
    return merged, added


def _parse_screening_with_layers(raw: str) -> ScreeningResult:
    errors: List[str] = []
    if _SCREENING_PARSER is not None:
        try:
            return _coerce_structured_result(ScreeningResult, _SCREENING_PARSER.parse(raw))
        except Exception as exc:
            errors.append(f"PydanticOutputParser: {exc}")
    try:
        return _parse_screening_result(raw)
    except Exception as exc:
        errors.append(f"local tolerant parser: {exc}")
    if ALLOW_MODEL_JSON_REPAIR and _SCREENING_FIXER is not None:
        try:
            return _coerce_structured_result(ScreeningResult, _SCREENING_FIXER.parse(raw))
        except Exception as exc:
            errors.append(f"OutputFixingParser: {exc}")
    raise ValueError("; ".join(errors) or "No screening parser available")


def _invoke_screening_model(prompt: str) -> Tuple[ScreeningResult, str, str]:
    native_error: Optional[Exception] = None
    if _SCREENING_NATIVE is not None:
        try:
            value = _SCREENING_NATIVE.invoke(prompt)
            parsed = _coerce_structured_result(ScreeningResult, value)
            return parsed, _message_to_text(value), "native-json-schema"
        except Exception as exc:
            native_error = exc

    raw = _invoke_text_model(_screener_text_llm, prompt)
    try:
        return _parse_screening_with_layers(raw), raw, "pydantic-parser"
    except Exception as parser_error:
        if native_error is not None:
            raise RuntimeError(
                f"native structured output failed: {native_error}; parser fallback failed: {parser_error}"
            ) from parser_error
        raise


def _invoke_screening(task: MultiSourcePathTask) -> Optional[AnalyzerTask]:
    prompt = task.cached_screening_prompt or _screening_prompt(task)
    if len(prompt) > MAX_TOTAL_PROMPT_CHARS:
        raise PromptBudgetError(
            f"Refusing to send oversized Screener prompt for {task.task_id}: "
            f"{len(prompt)}>{MAX_TOTAL_PROMPT_CHARS}."
        )
    start = time.perf_counter()
    parse_error: Optional[Exception] = None
    raw = ""
    output_mode = "failed"
    static_rescue_added = 0
    try:
        parsed, raw, output_mode = _invoke_screening_model(prompt)
        hypotheses = _normalize_hypotheses(task, parsed)
        if output_mode == "native-json-schema" and parsed.hypotheses and not hypotheses:
            # Native constrained decoding returned hypotheses but every one was
            # contentless template junk. That is degeneration, not a legitimate
            # "no hypothesis" answer: retry once without constrained decoding.
            raw = _invoke_text_model(_screener_text_llm, prompt)
            output_mode = "pydantic-parser"
            hypotheses = _normalize_hypotheses(task, _parse_screening_with_layers(raw))
        if SCREENER_STATIC_RESCUE:
            hypotheses, static_rescue_added = _merge_additive_static_hypotheses(
                task, hypotheses
            )
    except Exception as exc:
        parse_error = exc
        hypotheses = _static_rescue_hypotheses(task) if SCREENER_STATIC_RESCUE else []
    elapsed = time.perf_counter() - start

    if DEBUG_SCREENER_RAW:
        print(f"\n[Raw Screener {task.task_id} mode={output_mode}]\n{raw}\n")

    source_labels = ", ".join(
        f"{subpath.source_id}={subpath.source_display}"
        for subpath in task.source_subpaths
    )
    print(
        f"    -> [120B Screener] task={task.task_id}, batching={task.batching_mode}, "
        f"sources={len(task.source_subpaths)} [{source_labels}], "
        f"chain={' -> '.join(task.call_chain)}, raw_facts={len(_all_task_facts(task))}, "
        f"path_spine_facts={_task_prompt_fact_count(task)}, "
        f"sinks={len(_all_task_sinks(task))}, hypotheses={len(hypotheses)}, "
        f"static_rescue_added={static_rescue_added}, "
        f"ctx={task.selected_caller_depth}/{task.selected_callee_depth}, "
        f"code={task.code_context_mode}, fact_format={task.fact_render_mode}, "
        f"structured={output_mode}, input_chars={len(prompt)}, seconds={elapsed:.2f}"
    )
    if parse_error:
        print(f"       Structured-output warning: {parse_error}; static rescue={len(hypotheses)}")
    if not hypotheses:
        return None
    return AnalyzerTask(path_task=task, hypotheses=hypotheses)


def _finding_has_substance(item: Dict[str, Any], status: str) -> bool:
    """A verdict that carries only schema defaults is not a verdict at all.

    Constrained decoding can degenerate into template findings: the root cause
    is the schema placeholder and every evidence list is empty. Such findings
    must be treated as unusable no matter how their hypothesis_id was assigned
    (explicit, order-based, or adopted), otherwise a model stall is recorded as
    a real confirmation or rejection.
    """
    root_cause = _normalize_space(item.get("vulnerability_root_cause"))
    has_root_cause = (
        bool(root_cause)
        and root_cause != "No reasoning supplied."
        and bool(_meaningful_label(root_cause))
    )
    # defenses_considered is deliberately NOT a substance signal: it is a
    # schema-REQUIRED field, so constrained decoding always fills it (even when
    # degenerating, with a generic placeholder sentence). counterevidence and
    # proof_gaps are optional — non-empty means the model deliberately added
    # content.
    has_supporting_detail = bool(
        item.get("counterevidence")
        or item.get("proof_gaps")
    )
    if status == "Vulnerable":
        return has_root_cause
    return has_root_cause or has_supporting_detail


def _collect_findings_by_id(
    parsed: VerificationResult,
    expected_ids: Sequence[str],
) -> Dict[str, Dict[str, Any]]:
    findings_by_id: Dict[str, Dict[str, Any]] = {}
    conflicted_ids: set = set()
    for finding_model in parsed.findings:
        item = _normalize_finding_evidence_fields(_model_dump(finding_model))
        hypothesis_id = _canonical_hypothesis_id(item.get("hypothesis_id"), expected_ids)
        status = _normalize_vulnerability_status(item.get("is_vulnerable"))
        if hypothesis_id not in expected_ids or status is None:
            continue
        # IDs assigned positionally during parsing bypass the adoption branch
        # below, so the template-default guard must run here as well.
        if not _finding_has_substance(item, status):
            continue
        item["hypothesis_id"] = hypothesis_id
        item["is_vulnerable"] = status
        # A second substantive verdict for the same ID with a DIFFERENT status is a
        # contradiction, not a duplicate: keeping whichever came first would let the
        # model's output order silently decide the verdict. Drop both and let the
        # missing-verdict retry re-judge the hypothesis.
        existing = findings_by_id.get(hypothesis_id)
        if existing is not None:
            if existing.get("is_vulnerable") != status:
                del findings_by_id[hypothesis_id]
                conflicted_ids.add(hypothesis_id)
            continue
        if hypothesis_id in conflicted_ids:
            continue
        findings_by_id[hypothesis_id] = item
    if not findings_by_id and not conflicted_ids and len(expected_ids) == 1 and parsed.findings:
        # Constrained decoding sometimes degenerates into template findings with an
        # empty hypothesis_id (schema defaults echoed, real analysis stuffed into
        # counterevidence). When exactly one hypothesis was requested, any returned
        # verdict can only refer to it, so adopt the first substantive one. Findings
        # that carry only schema defaults are not verdicts: they must fall through
        # to the text-model fallback instead of being adopted as-is. A "Vulnerable"
        # verdict without a concrete root cause is never adoptable.
        for finding_model in parsed.findings:
            item = _normalize_finding_evidence_fields(_model_dump(finding_model))
            status = _normalize_vulnerability_status(item.get("is_vulnerable"))
            if status is None:
                continue
            if not _finding_has_substance(item, status):
                continue
            item["hypothesis_id"] = expected_ids[0]
            item["is_vulnerable"] = status
            findings_by_id[expected_ids[0]] = item
            break
    return findings_by_id


def _parse_verification_with_layers(
    raw: str,
    expected_ids: Sequence[str],
) -> VerificationResult:
    errors: List[str] = []
    if _VERIFICATION_PARSER is not None:
        try:
            parsed = _coerce_structured_result(
                VerificationResult,
                _VERIFICATION_PARSER.parse(raw),
            )
            # Re-run through the tolerant normalizer so aliases, null metadata, and
            # ID variants are canonicalized consistently.
            return _parse_verification_result(
                json.dumps(_model_dump(parsed), ensure_ascii=False),
                expected_ids,
            )
        except Exception as exc:
            errors.append(f"PydanticOutputParser: {exc}")
    try:
        return _parse_verification_result(raw, expected_ids)
    except Exception as exc:
        errors.append(f"local tolerant parser: {exc}")
    if ALLOW_MODEL_JSON_REPAIR and _VERIFICATION_FIXER is not None:
        try:
            fixed = _coerce_structured_result(
                VerificationResult,
                _VERIFICATION_FIXER.parse(raw),
            )
            return _parse_verification_result(
                json.dumps(_model_dump(fixed), ensure_ascii=False),
                expected_ids,
            )
        except Exception as exc:
            errors.append(f"OutputFixingParser: {exc}")
    raise ValueError("; ".join(errors) or "No verification parser available")


def _invoke_verification_model(
    prompt: str,
    expected_ids: Sequence[str],
) -> Tuple[Dict[str, Dict[str, Any]], str, str]:
    native_error: Optional[Exception] = None
    if _VERIFICATION_NATIVE is not None:
        try:
            value = _VERIFICATION_NATIVE.invoke(prompt)
            parsed = _coerce_structured_result(VerificationResult, value)
            # Native schema output guarantees structure, not semantic completeness.
            findings = _collect_findings_by_id(parsed, expected_ids)
            if findings or not expected_ids:
                return findings, _message_to_text(value), "native-json-schema"
            # Constrained decoding occasionally degenerates (template findings with
            # empty hypothesis_id). Treat zero usable verdicts as a native failure
            # and fall back to the unconstrained text model below.
            native_error = ValueError(
                "native structured output returned no usable verdicts"
            )
        except Exception as exc:
            native_error = exc

    raw = _invoke_text_model(_analyzer_text_llm, prompt)
    try:
        parsed = _parse_verification_with_layers(raw, expected_ids)
        return _collect_findings_by_id(parsed, expected_ids), raw, "pydantic-parser"
    except Exception as parser_error:
        if native_error is not None:
            raise RuntimeError(
                f"native structured output failed: {native_error}; parser fallback failed: {parser_error}"
            ) from parser_error
        raise


def _parse_or_repair_verification(
    raw: str,
    expected_ids: Sequence[str],
) -> Dict[str, Dict[str, Any]]:
    """Compatibility helper used by tests and external callers."""
    try:
        parsed = _parse_verification_with_layers(raw, expected_ids)
        return _collect_findings_by_id(parsed, expected_ids)
    except Exception as exc:
        if DEBUG_ANALYZER_RAW:
            print(f"[Analyzer parse/fix failed] {exc}")
        return {}


def _verify_hypothesis_subset(
    task: MultiSourcePathTask,
    hypotheses: Sequence[Dict[str, Any]],
    retry_label: str,
) -> Dict[str, Dict[str, Any]]:
    expected_ids = [item["hypothesis_id"] for item in hypotheses]
    if not expected_ids:
        return {}
    retry_prompt = (
        f"RETRY MODE: {retry_label}. Return exactly the required IDs {expected_ids}; "
        "do not summarize them into one holistic verdict.\n\n"
        + _verification_prompt(task, hypotheses)
    )
    try:
        findings, raw, output_mode = _invoke_verification_model(retry_prompt, expected_ids)
    except Exception as model_error:
        print(
            f"       Analyzer retry failed for {task.task_id} {expected_ids}: {model_error}"
        )
        return {}
    if DEBUG_ANALYZER_RAW:
        print(
            f"\n[Raw Analyzer Retry {task.task_id} {expected_ids} mode={output_mode}]\n"
            f"{raw}\n"
        )
    return findings


def _actionable_gap_requests(
    findings_by_id: Dict[str, Dict[str, Any]],
    expected_ids: Sequence[str],
) -> OrderedDict[str, List[Dict[str, str]]]:
    actionable_types = _PROOF_GAP_TYPES - {"external_runtime_semantics", "other"}
    output: OrderedDict[str, List[Dict[str, str]]] = OrderedDict()
    for hypothesis_id in expected_ids:
        item = findings_by_id.get(hypothesis_id)
        if not item:
            continue
        normalized = _normalize_finding_evidence_fields(dict(item))
        if not normalized["proof_gaps"] or normalized["confidence"] == "High":
            continue
        requests = [
            request
            for request in normalized["evidence_requests"]
            if request["gap_type"] in actionable_types
            and re.fullmatch(r"[A-Za-z_]\w*", request["symbol"] or "")
        ]
        if requests:
            output[hypothesis_id] = requests
    return output


_GAP_SYMBOL_STOPWORDS = {
    "if", "else", "for", "while", "return", "sizeof", "switch", "case", "break",
    "continue", "goto", "struct", "union", "enum", "typedef", "const", "static",
    "void", "int", "char", "long", "short", "unsigned", "signed", "float",
    "double", "size_t", "ssize_t", "bool", "true", "false", "null", "none",
    "the", "and", "not", "with", "from", "that", "this", "unknown", "missing",
    "unresolved", "cannot", "could", "whether", "vulnerable", "vulnerability",
    "evidence", "function", "macro", "definition", "caller", "callee",
}


def _extract_gap_candidate_symbols(text: Any) -> List[str]:
    """Extract identifier-shaped tokens worth resolving as gap evidence."""
    return _dedup_preserve_order(
        token
        for token in re.findall(r"[A-Za-z_]\w*", str(text or ""))
        if len(token) >= 3 and token.lower() not in _GAP_SYMBOL_STOPWORDS
    )


def _symbol_resolves_in_current_file(
    engine: StaticAnalysisEngine,
    symbol: str,
) -> Optional[str]:
    """Return the proof-gap request type when symbol resolves in the current file."""
    if not re.fullmatch(r"[A-Za-z_]\w*", symbol):
        return None
    if symbol in engine.defined_functions:
        return "missing_function_body"
    try:
        macro_map = extract_relevant_macro_definitions(
            engine.file_path,
            symbol,
            max_definitions=None,
            max_chars=4096,
        ) or {}
    except Exception:
        macro_map = {}
    if isinstance(macro_map, dict) and any(
        re.search(rf"^\s*#\s*define\s+{re.escape(symbol)}\b", str(definition), flags=re.M)
        for definition in macro_map.values()
    ):
        return "missing_macro_definition"
    return None


def _synthesized_rejected_gap_requests(
    task: MultiSourcePathTask,
    hypotheses: Sequence[Dict[str, Any]],
    findings_by_id: Dict[str, Dict[str, Any]],
    engine: StaticAnalysisEngine,
) -> OrderedDict[str, List[Dict[str, str]]]:
    """Orchestrator fallback for findings with unresolved proof gaps.

    The model is not required to emit structured evidence_requests. For any
    binary verdict ("Not Vulnerable" or "Vulnerable") with non-empty proof_gaps
    and confidence != High, candidate symbols are extracted from the proof gaps,
    the finding's root cause/path text, and unresolved source origins. Only
    identifiers resolving to a function or macro in the CURRENT file survive;
    each becomes a bounded evidence request fed through the standard single
    re-verify round. Confirmed verdicts need this round too: on patched code the
    decisive refuting fact (an init-time validation, a capacity definition, a
    clamp) often lives in a sibling function the focused context never showed.
    """
    output: OrderedDict[str, List[Dict[str, str]]] = OrderedDict()
    hypothesis_lookup = {item["hypothesis_id"]: item for item in hypotheses}
    for hypothesis_id, item in findings_by_id.items():
        hypothesis = hypothesis_lookup.get(hypothesis_id)
        if hypothesis is None:
            continue
        normalized = _normalize_finding_evidence_fields(dict(item))
        if _normalize_vulnerability_status(normalized.get("is_vulnerable")) not in (
            "Not Vulnerable", "Vulnerable"
        ):
            continue
        if not normalized["proof_gaps"] or normalized["confidence"] == "High":
            continue

        candidates: List[str] = []
        for text in normalized["proof_gaps"]:
            candidates.extend(_extract_gap_candidate_symbols(text))
        for field_name in ("vulnerability_root_cause", "vulnerable_path"):
            candidates.extend(_extract_gap_candidate_symbols(normalized.get(field_name)))
        candidates.extend(_extract_gap_candidate_symbols(
            hypothesis.get("root_cause_hypothesis")
        ))
        # Unresolved source origins often name the producer that stayed opaque.
        referenced_subpaths = set(_safe_list(hypothesis.get("relevant_subpath_ids")))
        for subpath in task.source_subpaths:
            if referenced_subpaths and subpath.subpath_id not in referenced_subpaths:
                continue
            if str(subpath.source_status or "").lower() == "precise":
                continue
            candidates.extend(_extract_gap_candidate_symbols(subpath.source_origin))

        requests: List[Dict[str, str]] = []
        for symbol in _dedup_preserve_order(candidates):
            if len(requests) >= MAX_PROOF_GAP_SYMBOLS:
                break
            gap_type = _symbol_resolves_in_current_file(engine, symbol)
            if gap_type is None:
                continue
            # Symbols already rendered in the prompt add no new evidence.
            if gap_type == "missing_function_body" and _function_body_is_present(task, symbol):
                continue
            if gap_type == "missing_macro_definition" and _macro_definition_is_present(task, symbol):
                continue
            requests.append({
                "gap_type": gap_type,
                "symbol": symbol,
                "reason": (
                    "orchestrator-synthesized from the finding's unresolved proof "
                    "gaps; no model evidence_request was emitted"
                ),
            })
        if requests:
            output[hypothesis_id] = requests
    return output


def _function_body_is_present(task: MultiSourcePathTask, function_name: str) -> bool:
    return bool(re.search(
        rf"^// [^\n]*Function: {re.escape(function_name)}\s*$",
        task.code_context or "",
        flags=re.M,
    ))


def _macro_definition_is_present(task: MultiSourcePathTask, macro_name: str) -> bool:
    return bool(re.search(
        rf"^\s*#\s*define\s+{re.escape(macro_name)}\b",
        task.macro_context or "",
        flags=re.M,
    ))


def _build_bounded_gap_evidence(
    task: MultiSourcePathTask,
    request_map: OrderedDict[str, List[Dict[str, str]]],
    engine: StaticAnalysisEngine,
    char_budget: int,
) -> Tuple[str, Dict[str, List[Dict[str, str]]]]:
    if char_budget <= 0 or MAX_PROOF_GAP_SYMBOLS <= 0:
        return "", {}

    requested: OrderedDict[str, Dict[str, Any]] = OrderedDict()
    for hypothesis_id, requests in request_map.items():
        for request in requests:
            entry = requested.setdefault(request["symbol"], {"request_pairs": []})
            entry["request_pairs"].append((hypothesis_id, request))

    blocks: List[str] = []
    resolved: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    used = 0
    resolved_symbols = 0
    for symbol, entry in requested.items():
        if resolved_symbols >= MAX_PROOF_GAP_SYMBOLS:
            break
        remaining = min(char_budget - used, MAX_PROOF_GAP_EVIDENCE_CHARS - used)
        if remaining <= 500:
            break

        block = ""
        evidence_kind = ""
        if _function_body_is_present(task, symbol):
            continue
        resolved_function = engine.resolve_evidence_function(symbol)
        if resolved_function is not None:
            code, source_path = resolved_function
            header = (
                f"// Proof-gap function evidence: {symbol} "
                f"(source: {source_path})\n"
            )
            selected = ContextBuilder._compact_support_code(
                code, max(0, remaining - len(header) - 2)
            )
            if selected:
                block = header + selected + "\n"
                evidence_kind = "function_body"
        elif not _macro_definition_is_present(task, symbol):
            try:
                macro_map = extract_relevant_macro_definitions(
                    engine.file_path,
                    symbol,
                    max_definitions=None,
                    max_chars=min(remaining, 4096),
                ) or {}
            except Exception:
                macro_map = {}
            definitions = [
                str(definition)
                for definition in macro_map.values()
                if re.search(
                    rf"^\s*#\s*define\s+{re.escape(symbol)}\b",
                    str(definition),
                    flags=re.M,
                )
            ] if isinstance(macro_map, dict) else []
            if definitions:
                block = (
                    f"// Proof-gap macro evidence: {symbol}\n"
                    + "\n".join(definitions)
                    + "\n"
                )
                evidence_kind = "macro_definition"

        if not block or len(block) > remaining:
            continue
        blocks.append(block)
        used += len(block)
        resolved_symbols += 1
        for hypothesis_id, request in _dedup_preserve_order(entry["request_pairs"]):
            resolved[hypothesis_id].append({
                **request,
                "resolved_as": evidence_kind,
            })

    if not blocks:
        return "", {}
    header = (
        "/* Bounded proof-gap evidence. These exact definitions were requested by the "
        "first verification pass and resolved from the current file only. */\n"
    )
    return header + "\n".join(blocks), {
        hypothesis_id: _dedup_preserve_order(requests)
        for hypothesis_id, requests in resolved.items()
    }


def _complete_actionable_proof_gaps(
    task: MultiSourcePathTask,
    hypotheses: Sequence[Dict[str, Any]],
    findings_by_id: Dict[str, Dict[str, Any]],
    engine: Optional[StaticAnalysisEngine],
) -> Dict[str, Dict[str, Any]]:
    if not PROOF_GAP_EXPANSION or engine is None:
        return {}
    expected_ids = [item["hypothesis_id"] for item in hypotheses]
    request_map = _actionable_gap_requests(findings_by_id, expected_ids)
    # Rejected findings rarely carry model-emitted evidence_requests; synthesize
    # bounded current-file requests from their proof gaps instead.
    for hypothesis_id, requests in _synthesized_rejected_gap_requests(
        task, hypotheses, findings_by_id, engine
    ).items():
        existing = request_map.setdefault(hypothesis_id, [])
        seen_symbols = {request["symbol"] for request in existing}
        existing.extend(
            request for request in requests if request["symbol"] not in seen_symbols
        )
    if not request_map:
        return {}

    hypothesis_lookup = {item["hypothesis_id"]: item for item in hypotheses}
    requested_hypotheses = [
        hypothesis_lookup[hypothesis_id]
        for hypothesis_id in expected_ids
        if hypothesis_id in request_map
    ]
    base_prompt_chars = len(_verification_prompt(task, requested_hypotheses))
    char_budget = min(
        MAX_PROOF_GAP_EVIDENCE_CHARS,
        max(0, MAX_VERIFICATION_PROMPT_CHARS - base_prompt_chars - 1024),
    )
    evidence, resolved = _build_bounded_gap_evidence(
        task, request_map, engine, char_budget
    )
    if not evidence or not resolved:
        return {}

    retry_hypotheses = [
        hypothesis_lookup[hypothesis_id]
        for hypothesis_id in expected_ids
        if hypothesis_id in resolved
    ]
    expanded_task = _clone_multisource_task(
        task, task.source_subpaths, task.prompt_chunk_index, task.prompt_chunk_total
    )
    expanded_task.task_id = f"{task.task_id}:proof-gap"
    expanded_task.code_context = (task.code_context + "\n\n" + evidence).strip()
    expanded_prompt_chars = len(_verification_prompt(expanded_task, retry_hypotheses))
    if expanded_prompt_chars + 256 > MAX_VERIFICATION_PROMPT_CHARS:
        print(
            f"       Proof-gap evidence skipped for {task.task_id}: expanded prompt "
            f"{expanded_prompt_chars}>{MAX_VERIFICATION_PROMPT_CHARS}."
        )
        return {}

    recovered = _verify_hypothesis_subset(
        expanded_task,
        retry_hypotheses,
        retry_label=(
            "bounded proof-gap completion; reconsider each verdict using the appended "
            "local definitions and report any proof gaps that still remain; judge each "
            "hypothesis on the combined evidence, in either direction"
        ),
    )
    for hypothesis_id, item in recovered.items():
        item["_proof_gap_expansion"] = {
            "resolved_requests": resolved.get(hypothesis_id, []),
            "added_evidence_chars": len(evidence),
            "review_rounds": 1,
        }
    if recovered:
        symbols = _dedup_preserve_order(
            request["symbol"]
            for requests in resolved.values()
            for request in requests
        )
        print(
            f"       Proof-gap completion for {task.task_id}: "
            f"hypotheses={len(recovered)}, symbols={symbols}, evidence_chars={len(evidence)}."
        )
    return recovered


def _incomplete_finding(
    task: MultiSourcePathTask,
    hypothesis: Dict[str, Any],
    reason: str,
    elapsed: float,
) -> Dict[str, Any]:
    hypothesis_id = str(hypothesis.get("hypothesis_id") or "[unknown]")
    screening_reason = _normalize_space(hypothesis.get("root_cause_hypothesis", ""))
    public: Dict[str, Any] = {
        "is_vulnerable": "Not Vulnerable",
        "vulnerability_type": "N/A",
        "cwe_id": "N/A",
        "vulnerability_root_cause": (
            f"[VERIFICATION_INCOMPLETE] task={task.task_id}, {hypothesis_id}: {reason}. "
            f"Screening hypothesis: {screening_reason or 'not available'}."
        ),
        "vulnerable_path": "N/A",
        "security_boundary": "Unknown",
        "boundary_status": "Unknown",
        "counterevidence": [],
        "proof_gaps": [reason],
        "confidence": "Low",
    }
    public["_meta"] = {
        "task_id": task.task_id,
        "hypothesis_id": hypothesis_id,
        "verification_incomplete": True,
        "review_mode": REVIEW_MODE,
        "exact_call_edges": list(task.exact_call_edges),
        "preverify_fingerprint": hypothesis.get("_preverify_fingerprint")
            or _hypothesis_causal_fingerprint(task, hypothesis, include_path=True),
        "root_cause_fingerprint": hypothesis.get("_root_cause_fingerprint")
            or _hypothesis_causal_fingerprint(task, hypothesis, include_path=False),
        "verification_seconds": round(elapsed, 3),
    }
    return public


def _invoke_verification(
    analyzer_task: AnalyzerTask,
    engine: Optional[StaticAnalysisEngine] = None,
) -> List[Dict[str, Any]]:
    """Verify one budget-fitted hypothesis batch without aborting the source file."""
    task = analyzer_task.path_task
    hypotheses = analyzer_task.hypotheses
    expected_ids = [item["hypothesis_id"] for item in hypotheses]
    prompt = analyzer_task.cached_verification_prompt or _verification_prompt(task, hypotheses)
    if DEBUG_ANALYZER_RAW:
        try:
            safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", task.task_id)
            with open(f"/tmp/vul_verify_prompt_{safe_id}.txt", "w") as dump_fh:
                dump_fh.write(prompt)
        except Exception:
            pass
    start = time.perf_counter()
    first_error: Optional[str] = None
    raw = ""
    output_mode = "failed"
    try:
        findings_by_id, raw, output_mode = _invoke_verification_model(prompt, expected_ids)
    except Exception as model_error:
        findings_by_id = {}
        first_error = f"model invocation/structured parsing failed: {model_error}"
    elapsed = time.perf_counter() - start
    if DEBUG_ANALYZER_RAW:
        print(f"\n[Raw Analyzer {task.task_id} mode={output_mode}]\n{raw}\n")

    if raw and not findings_by_id:
        first_error = first_error or "initial response contained no complete canonical verdicts"
    missing = [hypothesis_id for hypothesis_id in expected_ids if hypothesis_id not in findings_by_id]

    # Missing findings are substantive omissions. Re-verify only omitted hypotheses.
    if missing and ANALYZER_MISSING_BATCH_RETRY:
        missing_hypotheses = [
            item for item in hypotheses if item.get("hypothesis_id") in missing
        ]
        recovered = _verify_hypothesis_subset(
            task,
            missing_hypotheses,
            retry_label="batch recovery for omitted or invalid findings",
        )
        findings_by_id.update(recovered)
        missing = [hypothesis_id for hypothesis_id in expected_ids if hypothesis_id not in findings_by_id]

    # Final one-hypothesis retries prevent batch collapsing without affecting normal calls.
    if missing and ANALYZER_MISSING_SINGLE_RETRY:
        hypothesis_lookup = {item["hypothesis_id"]: item for item in hypotheses}
        for hypothesis_id in list(missing):
            recovered = _verify_hypothesis_subset(
                task,
                [hypothesis_lookup[hypothesis_id]],
                retry_label=f"single-hypothesis recovery for {hypothesis_id}",
            )
            findings_by_id.update(recovered)
        missing = [hypothesis_id for hypothesis_id in expected_ids if hypothesis_id not in findings_by_id]

    # One bounded completion pass is allowed only for exact local symbols requested
    # because of a material proof gap. It replaces the first verdict for those
    # hypotheses while preserving unresolved gaps in the second response.
    gap_recovered = _complete_actionable_proof_gaps(
        task, hypotheses, findings_by_id, engine
    )
    findings_by_id.update(gap_recovered)
    elapsed = time.perf_counter() - start

    output: List[Dict[str, Any]] = []
    hypothesis_lookup = {item["hypothesis_id"]: item for item in hypotheses}
    for hypothesis_id in expected_ids:
        hypothesis = hypothesis_lookup[hypothesis_id]
        if hypothesis_id not in findings_by_id:
            reason = first_error or "verifier omitted or returned an invalid verdict after all retries"
            output.append(_incomplete_finding(task, hypothesis, reason, elapsed))
            continue

        item = _normalize_finding_evidence_fields(findings_by_id[hypothesis_id])
        status = _normalize_vulnerability_status(item.get("is_vulnerable"))
        if status is None:
            output.append(_incomplete_finding(
                task,
                hypothesis,
                "verifier returned no canonical binary verdict",
                elapsed,
            ))
            continue
        public = {field: item.get(field, "N/A") for field in PUBLIC_FINDING_FIELDS}
        public["is_vulnerable"] = status
        for field_name in ("vulnerability_type", "cwe_id", "vulnerability_root_cause", "vulnerable_path"):
            if public.get(field_name) is None or not str(public.get(field_name)).strip():
                public[field_name] = "N/A"
        # The verdict answers a specific hypothesis, so placeholder type/CWE
        # labels inherit the hypothesis labels rather than leaking "N/A" into
        # the final report.
        if not _meaningful_label(public.get("cwe_id")):
            hypothesis_cwe = _meaningful_label(hypothesis.get("cwe_id"))
            if hypothesis_cwe:
                public["cwe_id"] = str(hypothesis.get("cwe_id")).strip()
        if not _meaningful_label(public.get("vulnerability_type")):
            hypothesis_type = _normalize_space(str(hypothesis.get("potential_vulnerability_type") or ""))
            if hypothesis_type:
                public["vulnerability_type"] = hypothesis_type
        nullable_origin_kind = str(item.get("nullable_origin_kind") or "").strip().lower()

        relevant_source_ids = _safe_list(hypothesis.get("relevant_source_ids"))
        relevant_subpath_ids = _safe_list(hypothesis.get("relevant_subpath_ids"))
        source_lookup = {
            subpath.source_id: {
                "source_identity": subpath.source_identity,
                "source_display": subpath.source_display,
                "subpath_id": subpath.subpath_id,
                "root_func": subpath.path_root_func or task.root_func,
                "call_chain": _subpath_call_chain(task, subpath),
                "exact_call_edges": _subpath_call_edges(task, subpath),
            }
            for subpath in task.source_subpaths
        }
        public["_meta"] = {
            "task_id": task.task_id,
            "hypothesis_id": hypothesis_id,
            "root_func": task.root_func,
            "nullable_origin_kind": nullable_origin_kind,
            "source_ids": relevant_source_ids,
            "subpath_ids": relevant_subpath_ids,
            "sources": [source_lookup[source_id] for source_id in relevant_source_ids if source_id in source_lookup],
            "target_function": task.target_function,
            "call_chain": list(task.call_chain),
            "exact_call_edges": list(task.exact_call_edges),
            "context_mode": sorted({
                subpath.context_mode for subpath in task.source_subpaths
                if subpath.subpath_id in relevant_subpath_ids
            }),
            "screening_root_cause": hypothesis.get("root_cause_hypothesis", ""),
            "screening_cwe_id": hypothesis.get("cwe_id", "N/A"),
            "screening_vulnerability_type": hypothesis.get("potential_vulnerability_type", "N/A"),
            "preverify_fingerprint": hypothesis.get("_preverify_fingerprint")
                or _hypothesis_causal_fingerprint(task, hypothesis, include_path=True),
            "root_cause_fingerprint": hypothesis.get("_root_cause_fingerprint")
                or _hypothesis_causal_fingerprint(task, hypothesis, include_path=False),
            "verification_incomplete": False,
            "review_mode": REVIEW_MODE,
            "evidence_requests": item.get("evidence_requests", []),
            "proof_gap_expansion": item.get("_proof_gap_expansion", {}),
            "lifecycle_backedge_relations": _format_lifecycle_backedge_relations(task),
            "verification_seconds": round(elapsed, 3),
        }
        output.append(public)

    confirmed = sum(item["is_vulnerable"] == "Vulnerable" for item in output)
    incomplete = sum(item.get("_meta", {}).get("verification_incomplete", False) for item in output)
    print(
        f"    -> [120B Verifier] task={task.task_id}, hypotheses={len(expected_ids)}, "
        f"confirmed={confirmed}, incomplete={incomplete}, proof_gap_rechecks={len(gap_recovered)}, "
        f"structured={output_mode}, input_chars={len(prompt)}, seconds={elapsed:.2f}"
    )
    return output




def _strict_vulnerable_match(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Merge only duplicate reports of the same concrete root cause.

    Equal path text alone is insufficient: an integer overflow and its downstream OOB
    consequence may legitimately share one path but remain distinct findings.
    """
    left_cwe = _meaningful_label(left.get("cwe_id"))
    right_cwe = _meaningful_label(right.get("cwe_id"))
    left_type = _meaningful_label(left.get("vulnerability_type"))
    right_type = _meaningful_label(right.get("vulnerability_type"))

    if left_cwe and right_cwe and left_cwe != right_cwe:
        return False
    if left_type and right_type and left_type != right_type:
        return False
    same_class = bool(left_cwe and right_cwe and left_cwe == right_cwe) or bool(
        left_type and right_type and left_type == right_type
    )
    if not same_class:
        return False

    left_meta = left.get("_meta", {}) or {}
    right_meta = right.get("_meta", {}) or {}
    left_fingerprint = str(left_meta.get("root_cause_fingerprint") or "")
    right_fingerprint = str(right_meta.get("root_cause_fingerprint") or "")
    if left_fingerprint and right_fingerprint and left_fingerprint == right_fingerprint:
        return True

    left_edges = tuple(left_meta.get("exact_call_edges", []) or [])
    right_edges = tuple(right_meta.get("exact_call_edges", []) or [])
    if left_edges and right_edges and left_edges != right_edges:
        return False

    left_path = _normalize_code(left.get("vulnerable_path"))
    right_path = _normalize_code(right.get("vulnerable_path"))
    left_root = _normalize_space(left.get("vulnerability_root_cause")).lower()
    right_root = _normalize_space(right.get("vulnerability_root_cause")).lower()

    if left_path and right_path and left_path == right_path and left_root == right_root:
        return True

    def tokens(value: Any) -> Set[str]:
        return {
            token.lower()
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(value or ""))
            if len(token) > 2
        }

    left_funcs = set(re.findall(r"\b[A-Za-z_]\w*\s*\(", left_path))
    right_funcs = set(re.findall(r"\b[A-Za-z_]\w*\s*\(", right_path))
    if left_funcs and right_funcs and left_funcs.isdisjoint(right_funcs):
        return False

    root_similarity = SequenceMatcher(None, left_root, right_root).ratio()
    path_similarity = SequenceMatcher(None, left_path.lower(), right_path.lower()).ratio()
    shared_path_tokens = len(tokens(left_path) & tokens(right_path))
    return root_similarity >= 0.88 and (
        path_similarity >= 0.82 or shared_path_tokens >= 6
    )


def _near_duplicate_same_cwe(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Looser same-CWE merge for reworded duplicates of one concrete root cause.

    The strict matcher keeps near-identical texts; hypothesis variants verified in
    different batches often reword the same defect just enough to evade it. Require
    the same CWE class, compatible call edges, heavy content-token overlap, and
    high root-cause similarity so genuinely distinct bugs (different
    objects/operations) stay separate.
    """

    left_cwe = _meaningful_label(left.get("cwe_id"))
    right_cwe = _meaningful_label(right.get("cwe_id"))
    if not left_cwe or not right_cwe or left_cwe != right_cwe:
        return False
    left_root = _normalize_space(left.get("vulnerability_root_cause")).lower()
    right_root = _normalize_space(right.get("vulnerability_root_cause")).lower()
    if not left_root or not right_root:
        return False

    # Distinct concrete call paths must not merge even when the prose is similar.
    left_edges = tuple((left.get("_meta", {}) or {}).get("exact_call_edges", []) or [])
    right_edges = tuple((right.get("_meta", {}) or {}).get("exact_call_edges", []) or [])
    if left_edges and right_edges and left_edges != right_edges:
        return False

    # Structural guard: when both findings name concrete code identifiers
    # (calls, field/member accesses) and share none, they describe different
    # objects or operations and must stay separate even with similar prose —
    # covers the case where call edges are missing on one or both sides.
    def structural_tokens(value: str) -> Set[str]:
        names = re.findall(r"\b([A-Za-z_]\w*)\s*\(", value)
        names += re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", value)
        return {name.lower() for name in names if len(name) > 2}

    left_struct = structural_tokens(f"{left_root} {left.get('vulnerable_path') or ''}")
    right_struct = structural_tokens(f"{right_root} {right.get('vulnerable_path') or ''}")
    if left_struct and right_struct and left_struct.isdisjoint(right_struct):
        return False

    def content_tokens(value: str) -> Set[str]:
        return {
            token.lower()
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value)
            if len(token) > 3
        }

    if len(content_tokens(left_root) & content_tokens(right_root)) < 8:
        return False
    return SequenceMatcher(None, left_root, right_root).ratio() >= 0.85


def _structural_root_cause_match(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Structured same-root-cause merge for reworded duplicate findings.

    Character-level similarity misses paraphrased duplicates of one defect (the
    verifier legitimately rewords the same root cause across batches). Instead
    require ALL of:
    - identical normalized CWE class (multi-CWE strings must match exactly);
    - same target function from verification metadata (both sides must carry it,
      otherwise the merge stays conservative and declines);
    - Jaccard >= 0.5 over a structural signature built from cited callees,
      field/member accesses, and security-relevant variable names (buffers,
      lengths, indices, offsets) in root cause + attack path prose.

    The same-function + shared-identifier requirements keep genuinely distinct
    defects (different objects, different operations, different functions)
    separate even when their prose sounds alike.
    """
    left_cwe = _meaningful_label(left.get("cwe_id"))
    right_cwe = _meaningful_label(right.get("cwe_id"))
    if not left_cwe or not right_cwe or left_cwe != right_cwe:
        return False

    left_meta = left.get("_meta", {}) or {}
    right_meta = right.get("_meta", {}) or {}
    left_func = _normalize_space(str(left_meta.get("target_function") or ""))
    right_func = _normalize_space(str(right_meta.get("target_function") or ""))
    if not left_func or not right_func or left_func != right_func:
        return False

    def structural_signature(finding: Dict[str, Any]) -> Set[str]:
        text = (
            f"{finding.get('vulnerability_root_cause') or ''} "
            f"{finding.get('vulnerable_path') or ''}"
        )
        names = re.findall(r"\b([A-Za-z_]\w*)\s*\(", text)
        names += re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", text)
        names += re.findall(
            r"\b([A-Za-z_]\w*(?:buf|len|size|count|idx|index|offset|num|addr|ptr)\w*)\b",
            text,
            flags=re.I,
        )
        return {name.lower() for name in names if len(name) > 2}

    left_sig = structural_signature(left)
    right_sig = structural_signature(right)
    if not left_sig or not right_sig:
        return False
    jaccard = len(left_sig & right_sig) / len(left_sig | right_sig)
    return jaccard >= 0.5


def _null_dereference_expressions(finding: Dict[str, Any]) -> Set[str]:
    label = " ".join([
        str(finding.get("cwe_id") or ""),
        str(finding.get("vulnerability_type") or ""),
    ]).upper()
    if "476" not in label and "NULL POINTER" not in label:
        return set()
    evidence = " ".join([
        str(finding.get("vulnerability_root_cause") or ""),
        str(finding.get("vulnerable_path") or ""),
    ])
    return {
        re.sub(r"\s+", "", item)
        for item in re.findall(
            r"\b[A-Za-z_]\w*\s*(?:(?:->|\.)\s*[A-Za-z_]\w*)+",
            evidence,
        )
        if item.count("->") + item.count(".") >= 2
    }


def _null_dereference_semantic_key(finding: Dict[str, Any]) -> str:
    expressions = _null_dereference_expressions(finding)
    return "CWE-476|" + "|".join(sorted(expressions)) if expressions else ""


def _unsupported_bare_null_parameter(finding: Dict[str, Any]) -> bool:
    """Enforce the prompt rule that a hypothetical caller contract is not null evidence.

    Fires regardless of the self-reported boundary_status: a verdict that claims
    an Established/Plausible boundary while its only null scenario is "a caller
    may pass NULL" has mislabeled the boundary (the prompt forbids that claim),
    so the boundary label must not shield it.
    """
    label = " ".join([
        str(finding.get("cwe_id") or ""),
        str(finding.get("vulnerability_type") or ""),
    ]).upper()
    if "476" not in label and "NULL POINTER" not in label:
        return False
    # Structured label first (union, never a rescue): the field is model-labeled,
    # so a concrete-looking label must not shield a hypothetical claim — the text
    # rule below stays as the adversarial backstop for mislabeled verdicts.
    meta_kind = str(
        (finding.get("_meta", {}) or {}).get("nullable_origin_kind") or ""
    ).strip().lower()
    if meta_kind == "hypothetical_caller":
        return True
    evidence = _normalize_space(" ".join([
        str(finding.get("vulnerability_root_cause") or ""),
        str(finding.get("vulnerable_path") or ""),
    ])).lower()
    hypothetical_caller = bool(re.search(
        r"(?:caller|call site|argument)\b.{0,100}\b(?:pass(?:es|ing)?|suppl(?:y|ies|ying)|provid(?:e|es|ing)|is|be|becomes?)\b.{0,40}\bnull\b|"
        r"\bnull\s+(?:argument|parameter)\b",
        evidence,
    ))
    concrete_nullable_origin = bool(re.search(
        r"\b(?:returns?|returned|assigned|initialized|set|becomes?|remains?|stays?|kept|left|still)\s+(?:to\s+)?null\b|"
        r"\bnull\b.{0,60}\b(?:return|assignment|allocation failure|error path|optional field|initiali[sz]ation|loop|iteration|condition|branch)\b|"
        r"\b(?:initiali[sz]ed?\s+(?:to|as)|declared|defaults?\s+to)\s+null\b|"
        r"\b(?:or|alternative|branch)\b.{0,100}\bnull\b",
        evidence,
    ))
    return hypothetical_caller and not concrete_nullable_origin


def _unsupported_lifecycle_relation(finding: Dict[str, Any]) -> bool:
    """Reject lifecycle claims contradicted by a mandatory refresh backedge."""
    label = " ".join([
        str(finding.get("cwe_id") or ""),
        str(finding.get("vulnerability_type") or ""),
    ]).upper()
    if not any(token in label for token in ("CWE-415", "CWE-416", "DOUBLE FREE", "USE-AFTER-FREE")):
        return False
    evidence = _normalize_space(" ".join([
        str(finding.get("vulnerability_root_cause") or ""),
        str(finding.get("vulnerable_path") or ""),
    ])).lower()
    relations = str(
        (finding.get("_meta", {}) or {}).get("lifecycle_backedge_relations") or ""
    )
    for variable in re.findall(r"refresh `([A-Za-z_]\w*)`", relations):
        pattern = rf"\b{re.escape(variable.lower())}\b"
        # A reassignment of a bare pointer variable says nothing about the
        # staleness of a field reached through it (`rdev = ERR_PTR(ret);`
        # does not refresh `rdev->ena_pin`). Only a bare mention of the
        # refreshed variable itself contradicts the claim.
        stripped = re.sub(
            pattern + r"\s*(?:->|\.)\s*[A-Za-z_]\w*",
            " ",
            evidence,
        )
        if re.search(pattern, stripped):
            return True

    if "CWE-415" in label or "DOUBLE FREE" in label:
        operation_ids = re.findall(r"\bOP\d+\b", evidence, flags=re.I)
        # A re-entry/loop double free legitimately reaches ONE static free site
        # more than once, so the "must cite two distinct operations" check only
        # applies to claims of a single execution freeing the same object twice.
        reentrant = bool(re.search(
            r"\bre-?entr|"
            r"\b(?:second|subsequent|later|another|repeated)\s+(?:call|invocation)\b|"
            r"\b(?:each|next|every)\s+iteration\b",
            evidence,
        ))
        if (
            not reentrant
            and "duplicate" in evidence
            and len(set(item.upper() for item in operation_ids)) < 2
        ):
            return True
    return False


def _internally_contradictory_boundary_claim(finding: Dict[str, Any]) -> bool:
    """Reject a verdict whose own proof gap negates its boundary assertion."""
    if _meaningful_label(finding.get("boundary_status")) == "ESTABLISHED":
        return False
    root = _normalize_space(" ".join([
        str(finding.get("vulnerability_root_cause") or ""),
        str(finding.get("vulnerable_path") or ""),
    ])).lower()
    gaps = _normalize_space(" ".join(
        str(item) for item in _safe_list(finding.get("proof_gaps"))
    )).lower()
    claims_control = "attacker-controlled" in root or "attacker controlled" in root
    gap_denies_control = bool(re.search(
        r"(?:cannot|can not|not possible to)\s+confirm\s+attacker control|"
        r"(?:source|origin).{0,80}(?:not shown|unknown).{0,80}(?:attacker|range)",
        gaps,
    ))
    return claims_control and gap_denies_control


def aggregate_findings(
    findings: Sequence[Dict[str, Any]],
    drop_log: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    vulnerable_representatives: List[Dict[str, Any]] = []
    not_vulnerable: List[Dict[str, Any]] = []
    exact_not_vulnerable_seen: Set[str] = set()

    for finding in findings:
        if finding.get("is_vulnerable") == "Vulnerable":
            drop_reason = None
            if _unsupported_bare_null_parameter(finding):
                drop_reason = "unsupported_bare_null_parameter"
            elif _unsupported_lifecycle_relation(finding):
                drop_reason = "unsupported_lifecycle_relation"
            elif _internally_contradictory_boundary_claim(finding):
                drop_reason = "internally_contradictory_boundary_claim"
            if drop_reason is not None:
                if drop_log is not None:
                    drop_log.append({
                        "reason": drop_reason,
                        "task_id": (finding.get("_meta", {}) or {}).get("task_id"),
                        "hypothesis_id": finding.get("hypothesis_id"),
                        "cwe_id": finding.get("cwe_id"),
                        "vulnerability_type": finding.get("vulnerability_type"),
                        "vulnerability_root_cause": finding.get("vulnerability_root_cause"),
                    })
                continue
            semantic_key = _null_dereference_semantic_key(finding)
            semantic_expressions = _null_dereference_expressions(finding)
            match = next(
                (
                    rep for rep in vulnerable_representatives
                    if (
                        semantic_expressions
                        and semantic_expressions
                        & _null_dereference_expressions(rep)
                    ) or (
                        semantic_key
                        and semantic_key == _null_dereference_semantic_key(rep)
                    ) or _strict_vulnerable_match(rep, finding)
                    or _near_duplicate_same_cwe(rep, finding)
                    or _structural_root_cause_match(rep, finding)
                ),
                None,
            )
            if match is None:
                vulnerable_representatives.append(dict(finding))
            else:
                if drop_log is not None and not (
                    _strict_vulnerable_match(match, finding)
                    or _near_duplicate_same_cwe(match, finding)
                ):
                    drop_log.append({
                        "reason": "structural_root_cause_merge",
                        "task_id": (finding.get("_meta", {}) or {}).get("task_id"),
                        "hypothesis_id": finding.get("hypothesis_id"),
                        "cwe_id": finding.get("cwe_id"),
                        "vulnerability_type": finding.get("vulnerability_type"),
                        "vulnerability_root_cause": finding.get("vulnerability_root_cause"),
                    })
                if len(str(finding.get("vulnerability_root_cause") or "")) > len(str(match.get("vulnerability_root_cause") or "")):
                    match["vulnerability_root_cause"] = finding["vulnerability_root_cause"]
                if len(str(finding.get("vulnerable_path") or "")) > len(str(match.get("vulnerable_path") or "")):
                    match["vulnerable_path"] = finding["vulnerable_path"]
        elif INCLUDE_REJECTED_FINDINGS:
            public = {field: finding.get(field, "N/A") for field in PUBLIC_FINDING_FIELDS}
            fingerprint = str((finding.get("_meta", {}) or {}).get("root_cause_fingerprint") or "")
            marker = fingerprint or json.dumps(public, sort_keys=True, ensure_ascii=False)
            if marker in exact_not_vulnerable_seen:
                continue
            exact_not_vulnerable_seen.add(marker)
            not_vulnerable.append(dict(finding))

    combined = vulnerable_representatives + not_vulnerable
    final_output = [
        {field: finding.get(field, "N/A") for field in PUBLIC_FINDING_FIELDS}
        for finding in combined
    ]
    return final_output



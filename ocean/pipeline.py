"""End-to-end file pipeline, batching, diagnostics, and the main entry point."""

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
    _parse_code_and_get_funcs,
    clear_analysis_caches,
)

from .budget import (
    _fit_task_to_prompt_budget,
    _sink_contributing_task_ids,
    _split_by_operation_attention_budget,
)
from .config import (
    CONTEXT_CALLEE_DEPTH,
    CONTEXT_CALLER_DEPTH,
    DIAG_DIR,
    DIFF_DIR,
    EVIDENCE_SOURCE_ROOTS,
    FALLBACK_MODE,
    FORCE_REPROCESS,
    MAX_CODE_CONTEXT_CHARS,
    MAX_HYPOTHESES_PER_VERIFICATION,
    MAX_LLM_CONCURRENCY,
    MAX_TOTAL_PROMPT_CHARS,
    MAX_VERIFICATION_PROMPT_CHARS,
    MODEL_NAME,
    MULTI_SOURCE_BATCHING,
    OUTPUT_DIR,
    PATCH_SCOPE_ENABLED,
    PATH_VARIANT_BATCHING,
    SAVE_DIAGNOSTICS,
    SCREENER_STATIC_RESCUE,
    SINGLE_STAGE,
    SOURCE_GLOB,
    STRUCTURED_OUTPUT_MODE,
    TRACE_ADAPTIVE,
    TRACE_CALLEE_DEPTH,
    TRACE_CALLEE_DEPTH_MAX,
    VERIFIER_STAGE_NAME,
    WORKFLOW_NAME,
)
from .context import (
    ContextBuilder,
)
from .engine import (
    StaticAnalysisEngine,
)
from .evidence import (
    _attach_lifetime_links,
    _attach_vec_counterevidence,
)
from .prompts import (
    _verification_prompt,
)
from .schemas import (
    _SCREENING_FIXER,
    _SCREENING_NATIVE,
    _SCREENING_PARSER,
    _VERIFICATION_FIXER,
    _VERIFICATION_NATIVE,
    _VERIFICATION_PARSER,
)
from .stages import (
    _consolidate_exact_duplicate_hypotheses,
    _incomplete_finding,
    _invoke_screening,
    _invoke_verification,
    _static_rescue_hypotheses,
    aggregate_findings,
)
from .structures import (
    AnalyzerTask,
    MultiSourcePathTask,
    SourcePathTask,
)
from .textutil import (
    _source_sink_marker,
    _meaningful_label,
    _prompt_facts_for_subpath,
    _normalize_code,
    _normalize_space,
    _normalize_string_list,
    _safe_int,
    _stable_hash,
)
from .tpt import (
    _all_task_sinks,
    _build_tpt_tasks_for_group,
    _concrete_operation_marker,
    _group_final_paths,
    _pack_source_path_tasks,
    _pack_terminal_function_variants,
)



def _build_all_path_tasks(
    engine: StaticAnalysisEngine,
    final_paths: Sequence[List[Dict[str, Any]]],
) -> List[MultiSourcePathTask]:
    groups = _group_final_paths(final_paths)
    context_builder = ContextBuilder(engine)
    source_tasks: List[SourcePathTask] = []

    print(
        f"  - Static paths: {len(final_paths)} exact deduplicated paths; "
        f"source/root groups: {len(groups)}."
    )
    for (root_func, _), group_paths in groups.items():
        source_tasks.extend(_build_tpt_tasks_for_group(
            root_func,
            group_paths,
            engine.call_graph_diagnostics,
        ))

    exact_path_tasks = _pack_source_path_tasks(source_tasks)
    packed_tasks = _pack_terminal_function_variants(exact_path_tasks)
    attention_tasks = [
        attention_task
        for task in packed_tasks
        for attention_task in _split_by_operation_attention_budget(task)
    ]
    tasks: List[MultiSourcePathTask] = []
    for task in attention_tasks:
        tasks.extend(_fit_task_to_prompt_budget(task, context_builder))

    if any(not task.source_subpaths or not _all_task_sinks(task) for task in tasks):
        raise RuntimeError("Generated a shared path task without source subpaths or terminal sinks.")

    expected = [
        json.dumps({
            "source_task_id": source_task.task_id,
            "function": sink.get("function"),
            "start_byte": sink.get("start_byte", -1),
            "operation": _normalize_code(sink.get("operation")),
            "type": sink.get("type"),
            "abstract_object": sink.get("abstract_object"),
        }, sort_keys=True, ensure_ascii=False)
        for source_task in source_tasks
        for sink in source_task.sinks
    ]
    assigned = [
        _source_sink_marker(subpath, sink, contributing_id)
        for task in tasks
        for subpath in task.source_subpaths
        for sink in subpath.sinks
        for contributing_id in _sink_contributing_task_ids(subpath, sink)
    ]
    if Counter(assigned) != Counter(expected):
        raise RuntimeError("Multi-source path packing lost or duplicated source-sink evidence.")

    unique_terminal_operations = {
        _concrete_operation_marker(
            sink.get("function", source_task.target_function),
            sink.get("start_byte", -1),
            sink.get("path_step", -1),
            sink.get("operation"),
            sink.get("controls"),
            sink.get("type", "Terminal"),
        )
        for source_task in source_tasks
        for sink in source_task.sinks
    }
    lifecycle_candidates = {
        _stable_hash({
            "object": fact.get("object_id") or fact.get("abstract_object"),
            "event": fact.get("event_kind"),
            "function": fact.get("function"),
            "start_byte": _safe_int(fact.get("start_byte"), -1),
            "code": _normalize_code(fact.get("code")),
        }, 32)
        for source_task in source_tasks
        for fact in source_task.facts
        if str(fact.get("event_kind") or "").upper() in {
            "ALIAS_CAPTURE", "OBJECT_REFERENCE", "RELEASE", "RELEASE_AGAIN",
            "INVALIDATE", "USE", "REFRESH", "REASSIGN", "OBJECT_REPLACEMENT",
            "OWNERSHIP_TRANSFER", "UNKNOWN_EFFECT",
        }
    }
    source_batch_savings = max(0, len(source_tasks) - len(exact_path_tasks))
    variant_batch_savings = max(0, len(exact_path_tasks) - len(packed_tasks))
    attention_splits = max(0, len(attention_tasks) - len(packed_tasks))
    budget_splits = max(0, len(tasks) - len(attention_tasks))
    print(
        f"  - Source-specific terminal paths: {len(source_tasks)}; "
        f"unique terminal operations: {len(unique_terminal_operations)}; "
        f"lifecycle event sites: {len(lifecycle_candidates)}; "
        f"exact-path families: {len(exact_path_tasks)}; "
        f"target-function families: {len(packed_tasks)}; final LLM tasks: {len(tasks)}; "
        f"source batching saved {source_batch_savings} task(s); "
        f"path-variant batching saved {variant_batch_savings} task(s); "
        f"attention budget introduced {attention_splits} split task(s); "
        f"prompt budgets introduced {budget_splits} split task(s)."
    )
    _attach_vec_counterevidence(tasks, engine)
    _attach_lifetime_links(tasks, engine)
    return tasks


def _hypothesis_review_family_key(hypothesis: Dict[str, Any]) -> Tuple[str, ...]:
    """Keep variants of one root cause together and unrelated mechanisms apart."""
    root = _normalize_space(hypothesis.get("root_cause_hypothesis", ""))
    member_expressions = sorted({
        re.sub(r"\s+", "", expression)
        for expression in re.findall(
            r"\b[A-Za-z_]\w*\s*->\s*[A-Za-z_]\w*", root
        )
    })
    lifecycle_object = str(hypothesis.get("_lifecycle_object_id") or "")
    static_kind = str(hypothesis.get("_static_rescue_kind") or "")
    return (
        _meaningful_label(hypothesis.get("cwe_id")),
        _meaningful_label(hypothesis.get("potential_vulnerability_type")),
        static_kind,
        lifecycle_object,
        "|".join(member_expressions),
    )


def _fit_analyzer_task_to_prompt_budget(task: AnalyzerTask) -> List[AnalyzerTask]:
    """Split complete root-cause families to avoid budget and semantic interference."""
    initial_prompt = _verification_prompt(task.path_task, task.hypotheses)
    if (
        len(task.hypotheses) <= MAX_HYPOTHESES_PER_VERIFICATION
        and len(initial_prompt) <= MAX_VERIFICATION_PROMPT_CHARS
    ):
        task.cached_verification_prompt = initial_prompt
        return [task]

    families: OrderedDict[Tuple[str, ...], List[Dict[str, Any]]] = OrderedDict()
    for hypothesis in task.hypotheses:
        families.setdefault(_hypothesis_review_family_key(hypothesis), []).append(hypothesis)

    chunks: List[List[Dict[str, Any]]] = []
    for family in families.values():
        current: List[Dict[str, Any]] = []
        for hypothesis in family:
            candidate = current + [hypothesis]
            exceeds_count = len(candidate) > MAX_HYPOTHESES_PER_VERIFICATION
            exceeds_chars = (
                len(_verification_prompt(task.path_task, candidate))
                > MAX_VERIFICATION_PROMPT_CHARS
            )
            if current and (exceeds_count or exceeds_chars):
                chunks.append(current)
                current = [hypothesis]
            else:
                current = candidate
        if current:
            chunks.append(current)

    fitted = [AnalyzerTask(path_task=task.path_task, hypotheses=chunk) for chunk in chunks]
    for fitted_task in fitted:
        fitted_task.cached_verification_prompt = _verification_prompt(
            fitted_task.path_task, fitted_task.hypotheses
        )
    expected = [item["hypothesis_id"] for item in task.hypotheses]
    assigned = [item["hypothesis_id"] for fitted_task in fitted for item in fitted_task.hypotheses]
    if Counter(assigned) != Counter(expected):
        raise RuntimeError(f"Verification prompt splitting lost/duplicated hypotheses for {task.path_task.task_id}.")

    oversized_singletons = [
        item.hypotheses[0]["hypothesis_id"]
        for item in fitted
        if len(item.hypotheses) == 1
        and len(item.cached_verification_prompt) > MAX_VERIFICATION_PROMPT_CHARS
    ]
    print(
        f"  - Verification prompt split by budget: {task.path_task.task_id}, "
        f"hypotheses={len(expected)} -> {len(fitted)} batches; "
        f"max_per_batch={MAX_HYPOTHESES_PER_VERIFICATION}; no hypothesis dropped."
    )
    if oversized_singletons:
        print(
            f"    Warning: single-hypothesis prompts still exceed budget for {oversized_singletons}; "
            "they are retained intact rather than silently truncating path evidence."
        )
    return fitted


def _safe_invoke_screening(task: MultiSourcePathTask) -> Optional[AnalyzerTask]:
    try:
        return _invoke_screening(task)
    except Exception as exc:
        print(f"    -> [Screener Task Error] {task.task_id}: {exc}")
        hypotheses = _static_rescue_hypotheses(task) if SCREENER_STATIC_RESCUE else []
        return AnalyzerTask(path_task=task, hypotheses=hypotheses) if hypotheses else None


def _safe_invoke_verification(
    task: AnalyzerTask,
    engine: Optional[StaticAnalysisEngine] = None,
) -> List[Dict[str, Any]]:
    try:
        return _invoke_verification(task, engine=engine)
    except Exception as exc:
        print(f"    -> [Verifier Task Error] {task.path_task.task_id}: {exc}")
        return [
            _incomplete_finding(
                task.path_task,
                hypothesis,
                f"internal verifier task error: {exc}",
                0.0,
            )
            for hypothesis in task.hypotheses
        ]


def _run_screening_batch(tasks: Sequence[MultiSourcePathTask]) -> List[AnalyzerTask]:
    if not tasks:
        return []
    print("\n--- [Stage 2.5: Operation-Aware Multi-Source 120B Screener] ---")
    if MAX_LLM_CONCURRENCY == 1:
        results = [
            _safe_invoke_screening(task)
            for task in tqdm(tasks, desc="  Screening Shared Paths")
        ]
    else:
        with ThreadPoolExecutor(max_workers=MAX_LLM_CONCURRENCY) as executor:
            results = list(tqdm(
                executor.map(_safe_invoke_screening, tasks),
                total=len(tasks),
                desc="  Screening Shared Paths",
            ))
    analyzer_tasks = [result for result in results if result is not None]
    print(
        f"  - Screening complete: {len(tasks)} operation-aware tasks -> "
        f"{len(analyzer_tasks)} verification tasks."
    )
    return analyzer_tasks


def _run_verification_batch(
    tasks: Sequence[AnalyzerTask],
    engine: Optional[StaticAnalysisEngine] = None,
) -> List[Dict[str, Any]]:
    if not tasks:
        return []
    print(f"\n--- [Stage 3: {VERIFIER_STAGE_NAME}] ---")
    consolidated_tasks = _consolidate_exact_duplicate_hypotheses(tasks)
    fitted_tasks = [
        fitted
        for task in consolidated_tasks
        for fitted in _fit_analyzer_task_to_prompt_budget(task)
    ]
    expected_ids = [
        (task.path_task.task_id, hypothesis["hypothesis_id"])
        for task in consolidated_tasks
        for hypothesis in task.hypotheses
    ]
    assigned_ids = [
        (task.path_task.task_id, hypothesis["hypothesis_id"])
        for task in fitted_tasks
        for hypothesis in task.hypotheses
    ]
    if Counter(assigned_ids) != Counter(expected_ids):
        raise RuntimeError("Verification batching lost or duplicated hypotheses.")
    if MAX_LLM_CONCURRENCY == 1:
        nested = [
            _safe_invoke_verification(task, engine=engine)
            for task in tqdm(fitted_tasks, desc="  Verifying Paths")
        ]
    else:
        with ThreadPoolExecutor(max_workers=MAX_LLM_CONCURRENCY) as executor:
            nested = list(tqdm(
                executor.map(
                    lambda analyzer_task: _safe_invoke_verification(
                        analyzer_task, engine=engine
                    ),
                    fitted_tasks,
                ),
                total=len(fitted_tasks),
                desc="  Verifying Paths",
            ))
    return [finding for group in nested for finding in group]


def _single_stage_findings(analyzer_tasks: Sequence[AnalyzerTask]) -> List[Dict[str, Any]]:
    """Ablation (VUL_SINGLE_STAGE=1): screening-only single stage. Every
    hypothesis becomes a Vulnerable finding with no second-pass review;
    findings still flow through the same aggregation/output layer."""
    findings: List[Dict[str, Any]] = []
    for analyzer_task in analyzer_tasks:
        task = analyzer_task.path_task
        for hypothesis in analyzer_task.hypotheses:
            boundary_assumption = str(hypothesis.get("security_boundary_assumption") or "")
            findings.append({
                "is_vulnerable": "Vulnerable",
                "vulnerability_type": hypothesis.get("potential_vulnerability_type") or "N/A",
                "cwe_id": hypothesis.get("cwe_id") or "N/A",
                "vulnerability_root_cause": hypothesis.get("root_cause_hypothesis") or "",
                "vulnerable_path": "; ".join(
                    _normalize_string_list(hypothesis.get("required_preconditions"))
                ) or "N/A",
                "security_boundary": boundary_assumption or "Unknown",
                "boundary_status": (
                    "Unknown"
                    if boundary_assumption.strip().lower() in {"", "unknown"}
                    else "Plausible"
                ),
                "counterevidence": [],
                "proof_gaps": [],
                "confidence": "Medium",
                "_meta": {
                    "task_id": task.task_id,
                    "hypothesis_id": hypothesis.get("hypothesis_id"),
                    "review_mode": "single_stage",
                    "single_stage": True,
                },
            })
    return findings


from functools import lru_cache as _patch_lru_cache


@_patch_lru_cache(maxsize=None)
def _patch_touched_functions(file_path: str) -> Optional[frozenset]:
    """Functions in the rebuilt source that the CVE patch diff touches.

    Matches normalized +/- hunk lines against tree-sitter function bodies
    ('-' lines hit the vul side, '+' lines hit the novul side) and supplements
    with function names from @@ hunk headers. Returns None (caller keeps
    full-file analysis) when the diff is missing, unparsable, or matches no
    function — never an empty set that would silently drop the file.
    """
    basename = os.path.basename(file_path)
    cve_id = basename.split("_")[0]
    diff_path = os.path.join(DIFF_DIR, f"{cve_id}_diff.txt")
    if not os.path.exists(diff_path):
        print(f"  - Patch-scope: no diff for {cve_id} at {diff_path}; keeping full-file analysis.")
        return None
    try:
        with open(diff_path, "r", encoding="utf-8", errors="ignore") as handle:
            diff_text = handle.read()
    except OSError as exc:
        print(f"  - Patch-scope: cannot read {diff_path} ({exc}); keeping full-file analysis.")
        return None

    needles: Set[str] = set()
    for raw in diff_text.splitlines():
        if not raw or raw[:3] in {"---", "+++"}:
            continue
        marker = raw[0]
        if marker not in {"-", "+"}:
            continue
        line = re.sub(r"\s+", " ", raw[1:]).strip()
        if len(line) >= 6 and re.search(r"[A-Za-z0-9]", line):
            needles.add(line)

    header_names: Set[str] = set()
    for match in re.finditer(r"^@@[^@]*@@\s*(.*)$", diff_text, re.MULTILINE):
        name_match = re.search(r"\b([A-Za-z_]\w*)\s*\(", match.group(1))
        if name_match:
            header_names.add(name_match.group(1))

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
        func_nodes = _parse_code_and_get_funcs(source)
    except Exception as exc:
        print(f"  - Patch-scope: source parse failed for {basename} ({exc}); keeping full-file analysis.")
        return None

    touched: Set[str] = set()
    for name, node in func_nodes.items():
        body = re.sub(r"\s+", " ", node.text.decode("utf8", errors="ignore"))
        if any(needle in body for needle in needles):
            touched.add(name)
    touched |= {name for name in header_names if name in func_nodes}
    if not touched:
        print(f"  - Patch-scope: no patched function matched in {basename}; keeping full-file analysis.")
        return None
    return frozenset(touched)


def _path_touches_functions(path: Sequence[Dict[str, Any]], touched: Set[str]) -> bool:
    for segment in path:
        chain = segment.get("current_call_chain") or []
        if touched.intersection(chain):
            return True
        sink_function = segment.get("sink_target_function")
        if sink_function and sink_function in touched:
            return True
    return False


def analyze_file(file_path: str) -> List[Dict[str, Any]]:
    print(f"\n==================== Analyzing File: {file_path} ====================")
    file_start = time.perf_counter()
    native_ready = _SCREENING_NATIVE is not None and _VERIFICATION_NATIVE is not None
    parser_ready = _SCREENING_PARSER is not None and _VERIFICATION_PARSER is not None
    fixer_ready = _SCREENING_FIXER is not None and _VERIFICATION_FIXER is not None
    print(
        f"  - Structured output: mode={STRUCTURED_OUTPUT_MODE}, native_ready={native_ready}, "
        f"pydantic_parser_ready={parser_ready}, output_fixer_ready={fixer_ready}; "
        f"multi_source_batching={MULTI_SOURCE_BATCHING}; "
        f"evidence_roots={len(EVIDENCE_SOURCE_ROOTS)}."
    )

    print("\n--- [Stage 1: Recall-Preserving Static Analysis] ---")
    engine = StaticAnalysisEngine(file_path)
    print(
        f"  - Call graph roots={len(engine.rooted_call_graphs)}, "
        f"defined functions={len(engine.defined_function_names)}, "
        f"diagnostics={engine.call_graph_diagnostics}"
    )
    static_start = time.perf_counter()
    final_paths = engine.analyze()
    print(
        f"  - Static analysis completed in {time.perf_counter() - static_start:.2f}s; "
        f"transfer_summary_hits={engine.transfer_summary_hits}, "
        f"transfer_summary_misses={engine.transfer_summary_misses}, "
        f"fallback_tasks={engine.fallback_task_count}, "
        f"uncovered_fallback_operations={engine.fallback_operation_count}, "
        f"fallback_omitted_by_rank={engine.fallback_omitted_count}, "
        f"recoverable_task_errors={len(engine.static_task_errors)}."
    )

    patch_functions = _patch_touched_functions(file_path) if PATCH_SCOPE_ENABLED else None
    if patch_functions:
        before_count = len(final_paths)
        scoped_paths = [
            path for path in final_paths
            if _path_touches_functions(path, patch_functions)
        ]
        if scoped_paths:
            final_paths = scoped_paths
            print(
                f"  - Patch-scope filter: {before_count} -> {len(final_paths)} path(s); "
                f"touched functions={sorted(patch_functions)}"
            )
        else:
            # Never let the filter turn a file into a silent "no paths" result:
            # zero survivors means the GT chain does not pass through the
            # matched functions, so full-file analysis is the safe call.
            print(
                f"  - Patch-scope filter: 0 of {before_count} path(s) survived "
                f"(touched={sorted(patch_functions)}); keeping full-file analysis."
            )

    tasks = _build_all_path_tasks(engine, final_paths)
    analyzer_tasks = _run_screening_batch(tasks)
    if SINGLE_STAGE:
        print("\n--- [Stage 3: SKIPPED (VUL_SINGLE_STAGE=1, screening-only ablation)] ---")
        raw_findings = _single_stage_findings(analyzer_tasks)
    else:
        raw_findings = _run_verification_batch(analyzer_tasks, engine=engine)
    incomplete_count = sum(
        finding.get("_meta", {}).get("verification_incomplete", False)
        for finding in raw_findings
    )
    proof_gap_rechecks = sum(
        bool(finding.get("_meta", {}).get("proof_gap_expansion"))
        for finding in raw_findings
    )
    aggregation_drops: List[Dict[str, Any]] = []
    final_findings = aggregate_findings(raw_findings, drop_log=aggregation_drops)
    if SAVE_DIAGNOSTICS:
        _save_diagnostics(
            file_path,
            path_count=len(final_paths),
            tasks=tasks,
            analyzer_tasks=analyzer_tasks,
            raw_findings=raw_findings,
            aggregation_drops=aggregation_drops,
            final_findings=final_findings,
            fallback_omitted=engine.fallback_omitted_count,
        )

    print(
        f"\nWorkflow finished: paths={len(final_paths)}, tasks={len(tasks)}, "
        f"verification_tasks={len(analyzer_tasks)}, raw_findings={len(raw_findings)}, "
        f"verification_incomplete={incomplete_count}, proof_gap_rechecks={proof_gap_rechecks}, "
        f"final_findings={len(final_findings)}, "
        f"total_seconds={time.perf_counter() - file_start:.2f}"
    )
    return final_findings


def _diag_quality_signals(
    tasks: Sequence[MultiSourcePathTask],
    fallback_omitted: int = 0,
) -> Dict[str, Any]:
    """Candidate-flooding quality signals: files with a high block-review share
    or large per-task fact counts have low signal-to-noise."""
    fallback_tasks = 0
    facts_shown = 0
    max_facts = 0
    for task in tasks:
        if not any(sp.context_mode == "block_fallback" for sp in task.source_subpaths):
            continue
        fallback_tasks += 1
        count = sum(
            1
            for sp in task.source_subpaths
            for fact in _prompt_facts_for_subpath(sp)
            if str(fact.get("event_kind") or "") == "UNCOVERED_HIGH_RISK_OPERATION"
        )
        facts_shown += count
        max_facts = max(max_facts, count)
    total = len(tasks)
    return {
        "block_fallback_tasks": fallback_tasks,
        "block_fallback_task_ratio": round(fallback_tasks / total, 4) if total else 0.0,
        "block_fallback_facts_shown": facts_shown,
        "block_fallback_facts_omitted_by_rank": fallback_omitted,
        "max_facts_per_fallback_task": max_facts,
    }


def _save_diagnostics(
    file_path: str,
    *,
    path_count: int,
    tasks: Sequence[MultiSourcePathTask],
    analyzer_tasks: Sequence[AnalyzerTask],
    raw_findings: Sequence[Dict[str, Any]],
    aggregation_drops: Sequence[Dict[str, Any]],
    final_findings: Sequence[Dict[str, Any]],
    fallback_omitted: int = 0,
) -> None:
    """Write <output>.diag.json for false-negative analysis. Never raises.

    Preserves what the main output discards: tasks the screener dropped with
    zero hypotheses, every raw verdict (accepted AND rejected, with
    counterevidence and proof gaps), and aggregation post-filter drops.
    """
    try:
        hypotheses_by_task: Dict[str, List[Dict[str, Any]]] = {}
        for analyzer_task in analyzer_tasks:
            hypotheses_by_task[analyzer_task.path_task.task_id] = [
                {
                    "hypothesis_id": hypothesis.get("hypothesis_id"),
                    "cwe_id": hypothesis.get("cwe_id"),
                    "potential_vulnerability_type": hypothesis.get(
                        "potential_vulnerability_type"
                    ),
                    "root_cause_hypothesis": hypothesis.get("root_cause_hypothesis"),
                    "suspected_broken_control": hypothesis.get(
                        "suspected_broken_control"
                    ),
                }
                for hypothesis in analyzer_task.hypotheses
            ]
        screened_out_tasks = []
        for task in tasks:
            if task.task_id in hypotheses_by_task:
                continue
            screened_out_tasks.append({
                "task_id": task.task_id,
                "target_function": task.target_function,
                "sink_operations": [
                    str(sink.get("operation") or "")[:120]
                    for subpath in task.source_subpaths
                    for sink in subpath.sinks
                ][:8],
            })
        verdicts = []
        for finding in raw_findings:
            meta = finding.get("_meta", {}) or {}
            verdicts.append({
                "task_id": meta.get("task_id"),
                "hypothesis_id": finding.get("hypothesis_id"),
                "is_vulnerable": finding.get("is_vulnerable"),
                "cwe_id": finding.get("cwe_id"),
                "vulnerability_type": finding.get("vulnerability_type"),
                "vulnerability_root_cause": finding.get("vulnerability_root_cause"),
                "vulnerable_path": finding.get("vulnerable_path"),
                "boundary_status": finding.get("boundary_status"),
                "counterevidence": finding.get("counterevidence"),
                "defenses_considered": finding.get("defenses_considered") or [],
                "proof_gaps": finding.get("proof_gaps"),
                "confidence": finding.get("confidence"),
                "verification_incomplete": bool(meta.get("verification_incomplete")),
                "proof_gap_expansion": bool(meta.get("proof_gap_expansion")),
            })
        payload = {
            "file": os.path.basename(file_path),
            "model": MODEL_NAME,
            "counts": {
                "paths": path_count,
                "tasks": len(tasks),
                "verification_tasks": len(analyzer_tasks),
                "screened_out_tasks": len(screened_out_tasks),
                "hypotheses": sum(len(h) for h in hypotheses_by_task.values()),
                "raw_findings": len(raw_findings),
                "aggregation_drops": len(aggregation_drops),
                "final_findings": len(final_findings),
            },
            # Candidate flooding is an observable quality signal: files with a
            # high block-review share / large per-task fact counts have low
            # signal-to-noise; downstream should manually review their results
            # rather than trusting them directly.
            "quality_signals": _diag_quality_signals(tasks, fallback_omitted),
            "screened_out_tasks": screened_out_tasks,
            "hypotheses_by_task": hypotheses_by_task,
            "verdicts": verdicts,
            "aggregation_drops": list(aggregation_drops),
        }
        diag_path = _diag_path_for_source(file_path)
        os.makedirs(os.path.dirname(diag_path), exist_ok=True)
        with open(diag_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        print(f"  - Diagnostics saved: {diag_path}")
    except Exception as exc:  # observability must never break detection
        print(f"  - Diagnostics save failed (ignored): {exc}")


def _output_path_for_source(source_file: str) -> str:
    base = os.path.splitext(os.path.basename(source_file))[0] + ".json"
    return os.path.join(OUTPUT_DIR, base)


def _diag_path_for_source(source_file: str) -> str:
    base = os.path.splitext(os.path.basename(source_file))[0] + ".json.diag.json"
    return os.path.join(DIAG_DIR, base)


def main() -> None:
    if not SOURCE_GLOB:
        raise SystemExit(
            "No input files configured. Pass --source-glob or set VUL_SOURCE_GLOB "
            "(e.g. '/data/src/*.c')."
        )
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    source_files = sorted(glob.glob(SOURCE_GLOB))
    if not source_files:
        raise SystemExit(f"VUL_SOURCE_GLOB matched no files: {SOURCE_GLOB!r}")
    print(f"{WORKFLOW_NAME}: found {len(source_files)} file(s).")
    trace_depth_label = (
        "unbounded"
        if TRACE_CALLEE_DEPTH < 0
        else (
            f"adaptive:{TRACE_CALLEE_DEPTH}-{TRACE_CALLEE_DEPTH_MAX}"
            if TRACE_ADAPTIVE and TRACE_CALLEE_DEPTH_MAX > TRACE_CALLEE_DEPTH
            else f"fixed:{TRACE_CALLEE_DEPTH}"
        )
    )
    print(
        f"Model={MODEL_NAME}, trace_depth={trace_depth_label}, "
        f"fallback={FALLBACK_MODE}, code_budget={MAX_CODE_CONTEXT_CHARS}, "
        f"screen_prompt_budget={MAX_TOTAL_PROMPT_CHARS}, "
        f"verify_prompt_budget={MAX_VERIFICATION_PROMPT_CHARS}, "
        f"context_depth=caller:{CONTEXT_CALLER_DEPTH}/callee:{CONTEXT_CALLEE_DEPTH}, "
        f"path_variant_batching={PATH_VARIANT_BATCHING}, "
        f"concurrency={MAX_LLM_CONCURRENCY}"
    )

    for source_file in tqdm(source_files, desc="Files"):
        output_path = _output_path_for_source(source_file)
        error_path = output_path + ".error"
        if os.path.exists(output_path) and not FORCE_REPROCESS:
            print(f"{output_path} has been processed; skipping.")
            continue

        try:
            findings = analyze_file(source_file)
            with open(output_path, "w", encoding="utf-8") as handle:
                json.dump(findings, handle, indent=2, ensure_ascii=False)
            if os.path.exists(error_path):
                os.remove(error_path)
            print(f"Saved unified Vulnerable/Not Vulnerable output: {output_path}")
        except Exception:
            full_traceback = traceback.format_exc()
            print("\n!!!!!!!!!!!!!! FATAL ERROR !!!!!!!!!!!!!!")
            print(full_traceback)
            with open(error_path, "w", encoding="utf-8") as handle:
                handle.write(full_traceback)
            # Do not write [] on failure; that would falsely look like a safe result.

    # Optional for long-lived processes; harmless in one-shot runs.
    clear_analysis_caches()


if __name__ == "__main__":
    main()



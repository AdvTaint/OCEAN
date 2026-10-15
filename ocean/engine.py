"""Static analysis engine facade over the tree-sitter backend."""

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
    analyze_conditional_init_candidates,
    analyze_lifecycle_paths,
    analyze_lifecycle_paths_by_param_index,
    analyze_null_deref_candidates,
    analyze_taint_paths,
    analyze_taint_paths_by_param_index,
    collect_macro_definitions_for_file,
    control_deps_at_byte,
    detect_relocation_idioms,
    extract_filtered_local_variables,
    generate_rooted_call_graphs,
    generate_rooted_call_graphs_with_metadata,
    get_code_from_file,
    get_funcnames_from_file,
    get_parameter_info,
    guard_facts_at_byte,
    sink_event_sequence,
    summarize_lifecycle_effects,
)

from .config import (
    EVIDENCE_SOURCE_ROOTS,
    FALLBACK_MAX_FACTS,
    FALLBACK_MODE,
    LIFECYCLE_EFFECT_SUMMARIES,
    MAX_EVIDENCE_SYMBOL_FILES,
    MAX_NULLABLE_ORIGIN_PATHS_PER_FILE,
    _TREE_SITTER_LANGUAGES_SO,
    _TSLanguage,
    _TSParser,
)
from .structures import (
    AnalysisTask,
)
from .textutil import (
    _balanced_region,
    _call_arguments,
    _call_edge_identity,
    _choose_alias_used,
    _normalize_code,
    _normalize_space,
    _safe_int,
    _safe_list,
    _source_identity,
    _stable_hash,
    compute_trace_depth_budget,
    extract_function_name_from_string,
    get_argument_positions,
)


_LIFECYCLE_TRIGGER = re.compile(
    r"\b(?:free|xmlFree|kfree|g_free|xfree|OPENSSL_free|delete|realloc|"
    r"GROW|SHRINK|RESIZE|EXPAND|REALLOC|"
    r"(?i:(?:grow|resize|realloc|expand|reserve)[A-Za-z_0-9]*|"
    r"[A-Za-z_]\w*(?:grow|resize|realloc|expand|reserve)\w*))\b"
)


_LIFECYCLE_OBS_TRIGGER = re.compile(
    r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*;|=\s*[A-Z][A-Z0-9_]{2,}\s*;"
)


_LIFECYCLE_OBS_ENABLED = os.environ.get("VUL_STALE_PTR_OBS", "1").strip().lower() not in {"0", "false", "off"}


def _lifecycle_pass_enabled(function_code: str, callee_effects: Dict[str, Any]) -> bool:
    if _LIFECYCLE_TRIGGER.search(function_code) or any(callee_effects.values()):
        return True
    return _LIFECYCLE_OBS_ENABLED and bool(_LIFECYCLE_OBS_TRIGGER.search(function_code))


_HIGH_RISK_FALLBACK_PATTERN = re.compile(
    r"(?:\[[^\]]+\]|\b(?:memcpy|memmove|strcpy|strncpy|sprintf|snprintf|"
    r"strcat|strlen|memcmp|read|recv|malloc|calloc|realloc|free|delete|"
    r"copy_to_user|copy_from_user|__copy_to_user|__copy_from_user|"
    r"get_user|put_user|memdup_user|"
    r"list_del(?:_rcu|_init)?|hlist_del(?:_rcu|_init)?|rb_erase|"
    r"list_add(?:_rcu|_tail)?|hlist_add\w*)\s*\(|"
    r"\b(?:GROW|RESIZE|EXPAND|REALLOC)\b|\+=|-=|\*=|<<=|>>=|\+\+|--)"
)


_BENIGN_SINK_CALL_TARGETS = frozenset({
    "spin_lock", "spin_unlock", "spin_lock_bh", "spin_unlock_bh",
    "spin_lock_irq", "spin_unlock_irq", "spin_lock_irqsave", "spin_unlock_irqrestore",
    "mutex_lock", "mutex_unlock", "mutex_lock_interruptible",
    "read_lock", "read_unlock", "read_lock_bh", "read_unlock_bh",
    "read_lock_irq", "read_unlock_irq", "read_lock_irqsave", "read_unlock_irqrestore",
    "write_lock", "write_unlock", "write_lock_bh", "write_unlock_bh",
    "write_lock_irq", "write_unlock_irq", "write_lock_irqsave", "write_unlock_irqrestore",
    "rcu_read_lock", "rcu_read_unlock",
    "local_bh_disable", "local_bh_enable",
    "preempt_disable", "preempt_enable", "might_sleep",
    "DBG", "printk", "pr_debug", "pr_info", "pr_notice", "pr_warn", "pr_err",
    "dev_dbg", "dev_info", "dev_warn", "dev_err",
    "netdev_dbg", "netdev_info", "netdev_warn", "netdev_err",
})


_BARE_SELF_CHECK_PATTERN = re.compile(
    r"^\s*(?:if|while|for)\s*\(\s*\(*\s*[A-Za-z_]\w*\s*\)*\s*\)\s*;?\s*$"
)


def _is_benign_sink_operation(operation: str, category: Optional[str] = None) -> bool:
    """Return True for locking/logging calls and bare one-variable self-checks.

    `category` is accepted for interface stability; filtering is purely
    operation-text based so fallback accounting can apply the same rule.
    """
    text = _normalize_space(operation or "")
    if not text:
        return False
    call_match = re.search(r"([A-Za-z_]\w*)\s*\(", text)
    if call_match and call_match.group(1) in _BENIGN_SINK_CALL_TARGETS:
        return True
    return bool(_BARE_SELF_CHECK_PATTERN.match(text))




def _split_top_level_boolean(expression: str, operator: str) -> List[str]:
    """Split a C condition on a top-level boolean operator."""
    parts: List[str] = []
    start = 0
    paren = bracket = brace = 0
    quote = ""
    escaped = False
    index = 0
    while index < len(expression):
        char = expression[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
            index += 1
            continue
        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            brace = max(0, brace - 1)
        elif not (paren or bracket or brace) and expression.startswith(operator, index):
            parts.append(expression[start:index].strip())
            index += len(operator)
            start = index
            continue
        index += 1
    parts.append(expression[start:].strip())
    return [part for part in parts if part]


def _branch_guarantees_nonnull(branch: str, pointer_name: str) -> bool:
    escaped = re.escape(pointer_name)
    null = r"(?:NULL|nullptr|0)"
    if re.search(rf"\b{escaped}\s*!=\s*{null}\b", branch):
        return True
    if re.search(rf"\b{null}\s*!=\s*{escaped}\b", branch):
        return True
    return bool(re.search(rf"(?:^|&&|\()\s*{escaped}\s*(?:&&|\)|$)", branch))


def _if_regions(function_code: str) -> List[Dict[str, Any]]:
    regions: List[Dict[str, Any]] = []
    for match in re.finditer(r"\bif\s*\(", function_code):
        opening = function_code.find("(", match.start())
        condition_region = _balanced_region(function_code, opening, "(", ")")
        if condition_region is None:
            continue
        _, condition_end = condition_region
        body_start = condition_end + 1
        while body_start < len(function_code) and function_code[body_start].isspace():
            body_start += 1
        if body_start >= len(function_code):
            continue
        if function_code[body_start] == "{":
            body_region = _balanced_region(function_code, body_start, "{", "}")
            if body_region is None:
                continue
            _, body_end = body_region
            content_start = body_start + 1
        else:
            body_end = function_code.find(";", body_start)
            if body_end < 0:
                continue
            content_start = body_start
        regions.append({
            "if_start": match.start(),
            "condition_start": opening + 1,
            "condition_end": condition_end,
            "condition": function_code[opening + 1:condition_end],
            "body_start": content_start,
            "body_end": body_end,
        })
    return regions


def _condition_guards_dereference(
    condition: str,
    pointer_name: str,
    local_dereference_offset: int,
) -> bool:
    prefix = condition[:max(0, local_dereference_offset)]
    escaped = re.escape(pointer_name)
    null = r"(?:NULL|nullptr|0)"
    guard = re.search(
        rf"(?:\b{escaped}\s*!=\s*{null}\b|\b{null}\s*!=\s*{escaped}\b)",
        prefix,
    )
    return bool(guard and "&&" in prefix[guard.end():])


def _disjunctive_null_guard_facts(
    function_code: str,
    function_name: str,
) -> List[Dict[str, Any]]:
    """Find dereferences guarded by only some top-level OR alternatives."""
    facts: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, str]] = set()
    regions = _if_regions(function_code)
    for outer in regions:
        condition = str(outer["condition"])
        alternatives = _split_top_level_boolean(condition, "||")
        if len(alternatives) < 2:
            continue
        body_start = int(outer["body_start"])
        body_end = int(outer["body_end"])
        body = function_code[body_start:body_end]

        for dereference in re.finditer(r"\b([A-Za-z_]\w*)\s*->", body):
            pointer_name = dereference.group(1)
            guarantees = [
                _branch_guarantees_nonnull(branch, pointer_name)
                for branch in alternatives
            ]
            if not any(guarantees) or all(guarantees):
                continue
            absolute = body_start + dereference.start()

            protected = False
            inside_nested_condition = False
            for nested in regions:
                if nested is outer:
                    continue
                condition_start = int(nested["condition_start"])
                condition_end = int(nested["condition_end"])
                nested_body_start = int(nested["body_start"])
                nested_body_end = int(nested["body_end"])
                nested_condition = str(nested["condition"])
                if condition_start <= absolute < condition_end:
                    inside_nested_condition = True
                    if _condition_guards_dereference(
                        nested_condition,
                        pointer_name,
                        absolute - condition_start,
                    ):
                        protected = True
                        break
                elif nested_body_start <= absolute <= nested_body_end:
                    nested_alternatives = _split_top_level_boolean(
                        nested_condition, "||"
                    )
                    if nested_alternatives and all(
                        _branch_guarantees_nonnull(branch, pointer_name)
                        for branch in nested_alternatives
                    ):
                        protected = True
                        break
            # Restrict the rescue to a dereference used by a nested decision. Other
            # statements may be protected by switch/case invariants that this lightweight
            # local analysis cannot prove without creating many speculative hypotheses.
            if protected or not inside_nested_condition:
                continue

            line_number = function_code.count("\n", 0, absolute) + 1
            marker = (line_number, pointer_name)
            if marker in seen:
                continue
            seen.add(marker)
            line_start = function_code.rfind("\n", 0, absolute) + 1
            line_end = function_code.find("\n", absolute)
            if line_end < 0:
                line_end = len(function_code)
            operation = _normalize_space(function_code[line_start:line_end])
            unsafe = [
                branch for branch, guaranteed in zip(alternatives, guarantees)
                if not guaranteed
            ]
            operation_id = _stable_hash({
                "function": function_name,
                "line": line_number,
                "kind": "DISJUNCTIVE_NULL_GUARD",
                "pointer": pointer_name,
                "condition": _normalize_code(condition),
            }, 24)
            facts.append({
                "event_kind": "DISJUNCTIVE_NULL_GUARD",
                "operation_id": operation_id,
                "operation_kind": "POINTER_DEREFERENCE",
                "code": operation,
                "normalized_code": _normalize_code(operation),
                "function": function_name,
                "line": line_number,
                "statement_index": line_number,
                "start_byte": absolute,
                "controls": [_normalize_space(condition)],
                "nullable_pointer": pointer_name,
                "unsafe_disjuncts": [_normalize_space(branch) for branch in unsafe],
            })
    return facts


class StaticAnalysisEngine:
    def __init__(self, file_path: str):
        self.file_path = file_path
        try:
            graph_bundle = generate_rooted_call_graphs_with_metadata(file_path)
        except Exception as exc:
            print(f"  - Call graph metadata warning: {exc}; trying basic call graph.")
            graph_bundle = None
        if graph_bundle:
            self.rooted_call_graphs = graph_bundle.get("rooted_graphs", {}) or {}
            self.call_graph_diagnostics = graph_bundle.get("diagnostics", {}) or {}
        else:
            try:
                self.rooted_call_graphs = generate_rooted_call_graphs(file_path) or {}
            except Exception as exc:
                print(f"  - Basic call graph generation failed: {exc}")
                self.rooted_call_graphs = {}
            self.call_graph_diagnostics = {}
        try:
            self.defined_function_names = [name for name in (get_funcnames_from_file(file_path) or []) if name]
        except Exception as exc:
            print(f"  - Function index warning: {exc}")
            self.defined_function_names = []
        self.defined_functions = set(self.defined_function_names)
        self.code_cache: Dict[str, str] = {}
        self.evidence_symbol_cache: Dict[
            str, Optional[Tuple[str, str]]
        ] = {}
        self.function_analysis_cache: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
        self.lifecycle_effect_cache: Dict[str, Dict[str, Any]] = {}
        self.lifecycle_summary_in_progress: Set[str] = set()
        self._lifecycle_macro_defs: Optional[Dict[str, Any]] = None
        self.local_variables_cache: Dict[str, List[str]] = {}
        self.callee_index: Dict[str, List[str]] = defaultdict(list)
        self.caller_index: Dict[str, List[str]] = defaultdict(list)
        self.static_task_errors: List[str] = []
        # (function, parameter_index) pairs already covered by a transitive task;
        # entry-point parameter seeding skips these to avoid duplicate sources.
        self._transitive_param_coverage: Set[Tuple[str, int]] = set()
        self.trace_depth_budget_cache: Dict[str, int] = {}
        self.transfer_summary_hits = 0
        self.transfer_summary_misses = 0
        self.fallback_task_count = 0
        self.fallback_operation_count = 0
        self.fallback_omitted_count = 0
        self._externally_invoked_cache: Optional[Set[str]] = None
        self._relocation_idioms_cache: Optional[List[Dict[str, Any]]] = None
        self._build_call_indices()

    def trace_depth_budget(self, entry_func: str) -> int:
        if entry_func not in self.trace_depth_budget_cache:
            self.trace_depth_budget_cache[entry_func] = compute_trace_depth_budget(
                self.rooted_call_graphs, entry_func
            )
        return self.trace_depth_budget_cache[entry_func]

    def _build_call_indices(self) -> None:
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for graph in self.rooted_call_graphs.values():
            for caller, callees in graph.items():
                adjacency[caller].update(callees or [])
        for caller, callees in adjacency.items():
            self.callee_index[caller] = sorted(callees)
            for callee in callees:
                self.caller_index[callee].append(caller)
        for callee in list(self.caller_index):
            self.caller_index[callee] = sorted(set(self.caller_index[callee]))

    @property
    def externally_invoked_functions(self) -> Set[str]:
        """Visible-unit entry points: defined functions with no in-file caller.

        The analysis unit is a fragment of a larger program, so a function that
        no visible code calls is invoked from outside the unit (another TU, or
        a framework callback through an ops table whose registration was cut
        from the unit). Such a function can be re-entered even though the call
        graph shows no callers.
        """
        if self._externally_invoked_cache is None:
            self._externally_invoked_cache = {
                name
                for name in self.defined_function_names
                if not self.caller_index.get(name)
            }
        return self._externally_invoked_cache

    def caller_lock_serialized(self, function_name: str) -> bool:
        """True when every in-file call site of function_name executes under a
        common caller-held spin lock (its flag/list accesses are then serialized,
        e.g. the patched CVE-2017-10661 wrapper around __timerfd_remove_cancel)."""
        callers = self.caller_index.get(function_name) or []
        if not callers:
            return False
        lock_re = re.compile(
            r"\bspin_lock(?:_irqsave|_irq|_bh|_nested)?\s*\(\s*&?\s*"
            r"([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*[,)]"
        )
        unlock_re = re.compile(
            r"\bspin_unlock(?:_irqrestore|_irq|_bh)?\s*\(\s*&?\s*"
            r"([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*[,)]"
        )
        call_re = re.compile(rf"\b{re.escape(function_name)}\s*\(")
        common: Optional[Set[str]] = None
        any_site = False
        for caller in callers:
            code = self.get_code(caller) or ""
            if not code:
                return False
            regions: List[Tuple[int, int, str]] = []
            for lock_match in lock_re.finditer(code):
                lock_obj = re.sub(r"\s+", "", lock_match.group(1))
                for unlock_match in unlock_re.finditer(code, lock_match.end()):
                    if re.sub(r"\s+", "", unlock_match.group(1)) == lock_obj:
                        regions.append((lock_match.start(), unlock_match.end(), lock_obj))
                        break
            for call_match in call_re.finditer(code):
                any_site = True
                covering = {
                    lock for start, end, lock in regions
                    if start <= call_match.start() <= end
                }
                if not covering:
                    return False
                common = covering if common is None else (common & covering)
                if not common:
                    return False
        return bool(any_site and common)

    @property
    def relocation_idioms(self) -> List[Dict[str, Any]]:
        """File-level codebase defensive idioms against backing-store relocation.

        Computed once per file from every defined function body; used to upgrade
        UNKNOWN lifecycle effects to MAY_RELOCATE with file-local provenance.
        """
        if self._relocation_idioms_cache is None:
            macro_defs = self._macro_defs()
            idioms: List[Dict[str, Any]] = []
            for name in self.defined_function_names:
                code = self.get_code(name)
                if not code:
                    continue
                try:
                    idioms.extend(detect_relocation_idioms(code, name, macro_defs))
                except Exception as exc:
                    self.static_task_errors.append(f"relocation_idioms({name}): {exc}")
            self._relocation_idioms_cache = idioms
            if idioms:
                print(
                    f"  - Relocation defensive idioms: {len(idioms)} site(s) "
                    f"({', '.join(item['site'] for item in idioms[:4])})."
                )
        return self._relocation_idioms_cache

    def get_code(self, function_name: str) -> Optional[str]:
        if function_name in self.code_cache:
            return self.code_cache[function_name]
        try:
            code = get_code_from_file(function_name, self.file_path)
        except Exception as exc:
            self.static_task_errors.append(f"get_code({function_name}): {exc}")
            print(f"  - Static code extraction warning for {function_name}: {exc}")
            return None
        if code:
            self.code_cache[function_name] = code
        return code

    def resolve_evidence_function(
        self,
        function_name: str,
    ) -> Optional[Tuple[str, str]]:
        """Resolve one exact function body: current file first, then bounded roots.

        Repository-root search only runs when VUL_EVIDENCE_ROOTS is explicitly
        configured; by default proof-gap completion never reads outside the file
        under analysis.
        """
        if function_name in self.evidence_symbol_cache:
            return self.evidence_symbol_cache[function_name]
        if function_name in self.defined_functions:
            code = self.get_code(function_name)
            resolved = (code, self.file_path) if code else None
            self.evidence_symbol_cache[function_name] = resolved
            return resolved
        if not EVIDENCE_SOURCE_ROOTS or not re.fullmatch(r"[A-Za-z_]\w*", function_name):
            self.evidence_symbol_cache[function_name] = None
            return None

        candidates: List[str] = []
        for root in EVIDENCE_SOURCE_ROOTS:
            if os.path.isfile(root):
                candidates.append(root)
                continue
            try:
                result = subprocess.run(
                    [
                        "rg", "-l", "--max-count", "1",
                        rf"\b{function_name}\s*\(",
                        "--glob", "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}",
                        root,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.static_task_errors.append(
                    f"evidence_search({function_name}, {root}): {exc}"
                )
                continue
            candidates.extend(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
            if len(candidates) >= MAX_EVIDENCE_SYMBOL_FILES:
                break

        seen_files: Set[str] = set()
        for candidate in candidates[:MAX_EVIDENCE_SYMBOL_FILES]:
            candidate = os.path.abspath(candidate)
            if candidate in seen_files or candidate == os.path.abspath(self.file_path):
                continue
            seen_files.add(candidate)
            try:
                code = get_code_from_file(function_name, candidate)
            except Exception as exc:
                self.static_task_errors.append(
                    f"evidence_get_code({function_name}, {candidate}): {exc}"
                )
                continue
            if code:
                resolved = (code, candidate)
                self.evidence_symbol_cache[function_name] = resolved
                return resolved

        self.evidence_symbol_cache[function_name] = None
        return None

    def _macro_defs(self) -> Dict[str, Any]:
        """Same-file macro table for lifecycle event recognition (cached)."""
        if self._lifecycle_macro_defs is None:
            try:
                self._lifecycle_macro_defs = collect_macro_definitions_for_file(
                    self.file_path
                )
            except Exception:
                self._lifecycle_macro_defs = {}
        return self._lifecycle_macro_defs

    def _lifecycle_effect_summary(self, function_name: str) -> Dict[str, Any]:
        if function_name in self.lifecycle_effect_cache:
            return self.lifecycle_effect_cache[function_name]
        if not LIFECYCLE_EFFECT_SUMMARIES:
            self.lifecycle_effect_cache[function_name] = {}
            return {}
        code = self.get_code(function_name) or ""
        if not code:
            self.lifecycle_effect_cache[function_name] = {}
            return {}
        if function_name in self.lifecycle_summary_in_progress:
            return {}
        self.lifecycle_summary_in_progress.add(function_name)
        try:
            child_effects = {
                callee: self._lifecycle_effect_summary(callee)
                for callee in self.callee_index.get(function_name, [])
                if callee in self.defined_functions and callee != function_name
            }
            summary = summarize_lifecycle_effects(
                code, function_name, callee_effects=child_effects,
                macro_defs=self._macro_defs(),
            ) or {}
        except Exception as exc:
            self.static_task_errors.append(f"lifecycle_summary({function_name}): {exc}")
            print(f"  - Lifecycle summary warning for {function_name}: {exc}")
            summary = {}
        finally:
            self.lifecycle_summary_in_progress.discard(function_name)
        self.lifecycle_effect_cache[function_name] = summary
        return summary

    def _callee_lifecycle_effects(self, function_name: str) -> Dict[str, Dict[str, Any]]:
        return {
            callee: self._lifecycle_effect_summary(callee)
            for callee in self.callee_index.get(function_name, [])
            if callee in self.defined_functions
        }

    def _field_carried_transfer_results(
        self,
        function_name: str,
        function_code: str,
    ) -> List[Dict[str, Any]]:
        """Recover object flow through a container field into a direct callee.

        The emitted facts are source statements and state transitions only. They do
        not assign a CWE or claim that an omitted field write is unsafe.
        """
        results: List[Dict[str, Any]] = []
        local_variables = set(self.local_variables_cache.get(function_name) or [])
        if not local_variables:
            local_variables = set(extract_filtered_local_variables(function_code) or [])
            self.local_variables_cache[function_name] = sorted(local_variables)
        internal_callees = self.callee_index.get(function_name, [])
        if not internal_callees:
            return []

        store_pattern = re.compile(
            r"(?P<container>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*|\[[^]\n]+\])*)"
            r"\s*=\s*(?P<object>[A-Za-z_]\w*)\s*;"
        )
        for store_match in store_pattern.finditer(function_code):
            container = _normalize_space(store_match.group("container"))
            object_name = store_match.group("object")
            if object_name not in local_variables or not re.search(r"(?:->|\.)", container):
                continue
            container_root_match = re.match(r"[A-Za-z_]\w*", container)
            if container_root_match is None:
                continue
            container_root = container_root_match.group(0)

            prefix = function_code[:store_match.start()]
            source_matches = list(re.finditer(
                rf"(?m)^[^;\n]*\b{re.escape(object_name)}\b[^;\n]*="
                rf"[^;\n]*\b[A-Za-z_]\w*\s*\([^;\n]*;",
                prefix,
            ))
            if not source_matches:
                continue
            source_match = source_matches[-1]
            source_statement = _normalize_space(source_match.group(0))
            producer_match = re.search(
                r"\b([A-Za-z_]\w*)\s*\(", source_statement.rsplit("=", 1)[-1]
            )
            if producer_match is None:
                continue
            producer = producer_match.group(1)
            store_statement = _normalize_space(store_match.group(0))

            state_events: List[Dict[str, Any]] = [{
                "event_kind": "OBJECT_CREATION_OR_ACQUISITION",
                "code": source_statement,
                "controls": [],
                "start_byte": len(function_code[:source_match.start()].encode("utf-8")),
                "operation_kind": (
                    "ZERO_INITIALIZING_ALLOCATION"
                    if producer in {"calloc", "kzalloc"}
                    else "NON_ZEROING_ALLOCATION"
                    if producer in {"malloc", "kmalloc"}
                    else "OBJECT_ACQUISITION"
                ),
                "object_id": f"field-carried::{function_name}::{object_name}",
            }]
            between = function_code[source_match.end():store_match.start()]
            field_write_pattern = re.compile(
                rf"(?m)^[^;\n]*\b{re.escape(object_name)}\s*->\s*"
                r"[A-Za-z_]\w*\s*=\s*[^;]+;"
            )
            for write_match in field_write_pattern.finditer(between):
                state_events.append({
                    "event_kind": "OBJECT_FIELD_WRITE",
                    "code": _normalize_space(write_match.group(0)),
                    "controls": [],
                    "start_byte": len(
                        function_code[:source_match.end() + write_match.start()].encode("utf-8")
                    ),
                    "object_id": f"field-carried::{function_name}::{object_name}",
                })
            state_events.append({
                "event_kind": "OBJECT_FIELD_STORE",
                "code": store_statement,
                "controls": [],
                "start_byte": len(function_code[:store_match.start()].encode("utf-8")),
                "object_id": f"field-carried::{function_name}::{object_name}",
            })

            suffix = function_code[store_match.end():]
            for callee in internal_callees:
                for call_match in re.finditer(rf"\b{re.escape(callee)}\s*\(", suffix):
                    absolute_start = store_match.end() + call_match.start()
                    semicolon = function_code.find(";", absolute_start)
                    if semicolon < 0:
                        continue
                    operation = _normalize_space(function_code[absolute_start:semicolon + 1])
                    arguments = _call_arguments(operation, callee)
                    if not any(
                        re.match(rf"[&*()\s]*{re.escape(container_root)}\b", argument)
                        for argument in arguments
                    ):
                        continue
                    sink_start_byte = len(
                        function_code[:absolute_start].encode("utf-8")
                    )
                    results.append({
                        "source_variable": [object_name, container_root],
                        "source_type": "field-carried object",
                        "taint_source": [source_statement],
                        "source_from_function": [producer],
                        "sinks": [{
                            "code": operation,
                            "category": "Field-Carried Object Transfer",
                            # [FIX] Was hardcoded []; now actually runs guard
                            # extraction on the synthetic sink's host statement
                            # (internally falls back to [] on failure)
                            "control_dependence": control_deps_at_byte(
                                function_code, sink_start_byte
                            ),
                            # [SHADOW] Structured guard/event facts: purely additive field
                            "guard_facts": guard_facts_at_byte(
                                function_code, sink_start_byte
                            ),
                            "event_sequence": sink_event_sequence(
                                function_code, sink_start_byte,
                                [object_name, container_root],
                                canonical_object=(
                                    f"field-carried::{function_name}::{object_name}"
                                ),
                                primary_var=object_name),
                            "start_byte": sink_start_byte,
                        }],
                        "path_kind": "dataflow",
                        "lifecycle_events": list(state_events),
                        "abstract_object": f"field-carried::{function_name}::{object_name}",
                        "analysis_summary": {
                            "source_strategy": "field_store_to_direct_callee",
                            "field_store": store_statement,
                        },
                    })
        return self._dedup_raw_results(results)

    def _analyze_function(self, task: AnalysisTask) -> List[Dict[str, Any]]:
        function_code = self.get_code(task.function_name)
        if not function_code:
            return []

        callee_effects = self._callee_lifecycle_effects(task.function_name)
        if task.is_transitive_analysis:
            if task.parameter_index is None:
                return []
            self._transitive_param_coverage.add((task.function_name, task.parameter_index))

            # Ordinary parameter transfer is independent of caller source names and
            # abstract-object generations. Compute it once per formal parameter.
            dataflow_key = (
                task.function_name,
                task.parameter_index,
                "__parameter_transfer__",
            )
            if dataflow_key in self.function_analysis_cache:
                self.transfer_summary_hits += 1
                dataflow_results = self.function_analysis_cache[dataflow_key]
            else:
                self.transfer_summary_misses += 1
                dataflow_results: List[Dict[str, Any]] = []
                result = analyze_taint_paths_by_param_index(
                    function_code, task.parameter_index
                )
                if result and result.get("sinks"):
                    dataflow_results.append(result)
                dataflow_results = self._dedup_raw_results(dataflow_results)
                self.function_analysis_cache[dataflow_key] = dataflow_results

            results = list(dataflow_results)

            # Lifecycle transfer remains object-generation specific. This retains
            # same-object semantics without re-running ordinary AST propagation.
            lifecycle_key = (
                task.function_name,
                task.parameter_index,
                task.abstract_object_hint or "",
                "__parameter_lifecycle__",
            )
            if lifecycle_key in self.function_analysis_cache:
                self.transfer_summary_hits += 1
                lifecycle_results = self.function_analysis_cache[lifecycle_key]
            else:
                self.transfer_summary_misses += 1
                lifecycle_results: List[Dict[str, Any]] = []
                if _lifecycle_pass_enabled(function_code, callee_effects):
                    lifecycle_results.extend(_safe_list(analyze_lifecycle_paths_by_param_index(
                        function_code,
                        task.parameter_index,
                        function_name=task.function_name,
                        abstract_object_hint=task.abstract_object_hint,
                        callee_effects=callee_effects,
                        macro_defs=self._macro_defs(),
                        caller_names=list(self.caller_index.get(task.function_name, [])),
                        externally_invoked=task.function_name in self.externally_invoked_functions,
                        relocation_idioms=self.relocation_idioms,
                        caller_serialized=self.caller_lock_serialized(task.function_name),
                    )))
                lifecycle_results = self._dedup_raw_results(lifecycle_results)
                self.function_analysis_cache[lifecycle_key] = lifecycle_results

            results.extend(lifecycle_results)
            return self._dedup_raw_results(results)

        cache_key = (task.function_name, "__local__")
        if cache_key in self.function_analysis_cache:
            return self.function_analysis_cache[cache_key]

        variables = self.local_variables_cache.get(task.function_name)
        if variables is None:
            variables = extract_filtered_local_variables(function_code) or []
            self.local_variables_cache[task.function_name] = variables

        results: List[Dict[str, Any]] = []
        for variable in variables:
            result = analyze_taint_paths(function_code, variable)
            if result and result.get("sinks"):
                results.append(result)

        # Preserve object state carried through a container field into a direct
        # internal callee. This is directional evidence, not container/object aliasing.
        results.extend(self._field_carried_transfer_results(
            task.function_name, function_code
        ))

        # Additive object-centric lifecycle pass. Callee summaries instantiate
        # wrapper effects such as `release(arg0)` at the concrete caller callsite.
        if _lifecycle_pass_enabled(function_code, callee_effects):
            results.extend(_safe_list(analyze_lifecycle_paths(
                function_code,
                task.function_name,
                callee_effects=callee_effects,
                macro_defs=self._macro_defs(),
                caller_names=list(self.caller_index.get(task.function_name, [])),
                externally_invoked=task.function_name in self.externally_invoked_functions,
                relocation_idioms=self.relocation_idioms,
                caller_serialized=self.caller_lock_serialized(task.function_name),
            )))

        # Additive nullable-origin pass: local pointers returned by calls (or
        # inline call results) dereferenced without a dominating NULL check.
        try:
            results.extend(
                result
                for result in _safe_list(
                    analyze_null_deref_candidates(function_code, task.function_name)
                )
                if result and result.get("sinks")
            )
        except Exception as exc:
            self.static_task_errors.append(
                f"null_deref_candidates({task.function_name}): {exc}"
            )

        # Additive conditional-init pass (N3): NULL/uninitialized pointer locals
        # whose only definitions are guard-controlled, dereferenced without a
        # dominating check — the state-style CWE-476 root shape.
        try:
            results.extend(
                result
                for result in _safe_list(
                    analyze_conditional_init_candidates(function_code, task.function_name)
                )
                if result and result.get("sinks")
            )
        except Exception as exc:
            self.static_task_errors.append(
                f"cond_init_candidates({task.function_name}): {exc}"
            )

        # Entry-point parameter seeding. Call-graph roots without in-file callers
        # never receive a transitive parameter task, so each formal parameter is
        # seeded as a source and marked for downstream prompt rendering.
        if (
            task.function_name in self.rooted_call_graphs
            and not self.caller_index.get(task.function_name)
        ):
            for parameter_index in range(self._entry_parameter_count(function_code)):
                if (task.function_name, parameter_index) in self._transitive_param_coverage:
                    continue
                try:
                    seeded = analyze_taint_paths_by_param_index(
                        function_code, parameter_index
                    )
                except Exception as exc:
                    self.static_task_errors.append(
                        f"entry_param_seed({task.function_name}, {parameter_index}): {exc}"
                    )
                    continue
                if not seeded or not seeded.get("sinks"):
                    continue
                seeded = dict(seeded)
                seeded["source_from_function"] = [
                    f"{name} [Entry Parameter]"
                    for name in _safe_list(seeded.get("source_from_function"))
                ] or ["[Entry Parameter]"]
                # The marker must also survive in taint_source: source_origin is
                # rendered from taint_source, not from source_from_function.
                seeded["taint_source"] = [
                    f"{origin} [Entry Parameter]"
                    for origin in _safe_list(seeded.get("taint_source"))
                ]
                results.append(seeded)

        results = self._dedup_raw_results(results)
        self.function_analysis_cache[cache_key] = results
        return results

    @staticmethod
    def _entry_parameter_count(function_code: str, cap: int = 6) -> int:
        """Enumerate formal parameters through the backend grammar (bounded)."""
        if _TSLanguage is None or _TSParser is None:
            return cap
        try:
            language = _TSLanguage(_TREE_SITTER_LANGUAGES_SO, "c")
            parser = _TSParser()
            parser.set_language(language)
            root_node = parser.parse(function_code.encode("utf8")).root_node
        except Exception:
            return cap
        count = 0
        for index in range(cap):
            try:
                info = get_parameter_info(root_node, index)
            except Exception:
                break
            if not info or not info.get("name"):
                break
            count += 1
        # A grammar failure falls back to probing every index below the cap;
        # analyze_taint_paths_by_param_index ignores out-of-range indices.
        return count

    @staticmethod
    def _dedup_raw_results(results: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for result in results:
            signature = {
                "path_kind": result.get("path_kind", "dataflow"),
                "source_variable": sorted(_safe_list(result.get("source_variable"))),
                "taint_source": sorted(_normalize_code(x) for x in _safe_list(result.get("taint_source"))),
                "source_from_function": sorted(_safe_list(result.get("source_from_function"))),
                "abstract_object": result.get("abstract_object", ""),
                "lifecycle_kind": result.get("lifecycle_kind", ""),
                "sinks": sorted(
                    (
                        _normalize_code(sink.get("code")),
                        sink.get("category", ""),
                        _safe_int(sink.get("start_byte"), -1),
                        tuple(sorted(_safe_list(sink.get("control_dependence")))),
                    )
                    for sink in _safe_list(result.get("sinks"))
                ),
                "lifecycle_events": [
                    (
                        event.get("event_kind"),
                        event.get("object_id") or event.get("abstract_object"),
                        _safe_int(event.get("start_byte", event.get("statement_index")), -1),
                        _normalize_code(event.get("code")),
                    )
                    for event in _safe_list(result.get("lifecycle_events"))
                ],
            }
            marker = json.dumps(signature, sort_keys=True, ensure_ascii=False)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(result)
        return deduped

    @staticmethod
    def _risk_operation_kind(code: str) -> str:
        normalized = code.lower()
        if re.search(
            r"\b(?:list_del(?:_rcu|_init)?|hlist_del(?:_rcu|_init)?|rb_erase|"
            r"list_add(?:_rcu|_tail)?|hlist_add\w*)\s*\(",
            normalized,
        ):
            return "CONTAINER_STATE_MUTATION"
        if re.search(r"\b(?:free|delete)\s*\(", normalized):
            return "RELEASE"
        if re.search(r"\b(?:malloc|calloc|realloc)\s*\(", normalized):
            return "ALLOCATION"
        if re.search(r"\b(?:memcpy|memmove|strcpy|strncpy|sprintf|snprintf|strcat)\s*\(", normalized):
            return "MEMORY_COPY_OR_WRITE"
        if re.search(r"\b(?:memcmp|strlen|read|recv)\s*\(", normalized):
            return "MEMORY_READ_OR_INPUT"
        if re.search(r"\b(?:GROW|RESIZE|EXPAND|REALLOC)\b", code):
            return "STORAGE_RESIZE"
        return "ARITHMETIC_OR_UPDATE"

    def _high_risk_operation_facts(self, function_name: str) -> List[Dict[str, Any]]:
        """Assign a stable function/location ID to each fallback-worthy operation."""

        function_code = self.get_code(function_name) or ""
        facts: List[Dict[str, Any]] = []
        for line_number, line in enumerate(function_code.splitlines(), start=1):
            if not _HIGH_RISK_FALLBACK_PATTERN.search(line):
                continue
            # Keep fallback accounting consistent with the path-level benign-sink
            # filter: removed operations must not reappear as block-review tasks.
            if _is_benign_sink_operation(line, None):
                continue
            normalized = _normalize_code(line)
            operation_kind = self._risk_operation_kind(line)
            operation_id = _stable_hash({
                "function": function_name,
                "line": line_number,
                "kind": operation_kind,
                "code": normalized,
            }, 24)
            facts.append({
                "event_kind": "UNCOVERED_HIGH_RISK_OPERATION",
                "operation_id": operation_id,
                "operation_kind": operation_kind,
                "code": _normalize_space(line),
                "normalized_code": normalized,
                "function": function_name,
                "line": line_number,
                "statement_index": line_number,
                "start_byte": -1,
                "controls": [],
            })

        # These locally provable guard defects are added even though a plain member
        # dereference is not otherwise treated as a fallback-worthy operation.
        existing_ids = {str(fact.get("operation_id")) for fact in facts}
        for fact in _disjunctive_null_guard_facts(function_code, function_name):
            if str(fact.get("operation_id")) not in existing_ids:
                facts.append(fact)
                existing_ids.add(str(fact.get("operation_id")))
        return facts

    @staticmethod
    def _line_for_local_byte_offset(function_code: str, start_byte: Any) -> int:
        offset = _safe_int(start_byte, -1)
        encoded = function_code.encode("utf-8")
        if offset < 0 or offset > len(encoded):
            return -1
        return encoded[:offset].count(b"\n") + 1

    def _covered_high_risk_operation_ids(
        self,
        function_name: str,
        raw_results: Sequence[Dict[str, Any]],
        risk_facts: Sequence[Dict[str, Any]],
    ) -> Set[str]:
        """Match precise sink/event sites to operation IDs with a text fallback."""

        function_code = self.get_code(function_name) or ""
        by_line: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for fact in risk_facts:
            by_line[_safe_int(fact.get("line"), -1)].append(fact)

        covered: Set[str] = set()
        evidence_items: List[Tuple[str, int]] = []
        for result in raw_results:
            for source in _safe_list(result.get("taint_source")):
                evidence_items.append((_normalize_code(source), -1))
            for sink in _safe_list(result.get("sinks")):
                evidence_items.append((
                    _normalize_code(sink.get("code")),
                    _safe_int(sink.get("start_byte"), -1),
                ))
            for event in _safe_list(result.get("lifecycle_events")):
                evidence_items.append((
                    _normalize_code(event.get("code")),
                    _safe_int(event.get("start_byte", event.get("statement_index")), -1),
                ))

        for evidence_code, start_byte in evidence_items:
            line_number = self._line_for_local_byte_offset(function_code, start_byte)
            for fact in by_line.get(line_number, []):
                covered.add(str(fact["operation_id"]))
            if not evidence_code:
                continue
            for fact in risk_facts:
                risky = str(fact.get("normalized_code") or "")
                if risky and (evidence_code in risky or risky in evidence_code):
                    covered.add(str(fact["operation_id"]))
        return covered

    def _fallback_risk_facts(
        self,
        function_name: str,
        raw_results: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if FALLBACK_MODE == "off":
            return []
        risk_facts = self._high_risk_operation_facts(function_name)
        if FALLBACK_MODE == "always":
            return risk_facts
        if FALLBACK_MODE == "missing":
            return [] if raw_results else risk_facts
        covered = self._covered_high_risk_operation_ids(
            function_name, raw_results, risk_facts
        )
        return [
            fact for fact in risk_facts
            if str(fact.get("operation_id")) not in covered
        ]

    @staticmethod
    def _function_param_names(function_code: str, function_name: str) -> List[str]:
        """Best-effort parameter names from the function signature (ranking only)."""
        match = re.search(rf"\b{re.escape(function_name)}\s*\(([^)]*)\)", function_code or "")
        if not match:
            return []
        names: List[str] = []
        for param in match.group(1).split(","):
            param = param.strip()
            if not param or param == "void":
                continue
            name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", param)
            if name_match and name_match.group(1) not in {
                "void", "int", "char", "long", "short", "unsigned", "signed",
                "struct", "const", "static", "size_t",
            }:
                names.append(name_match.group(1))
        return names

    _FALLBACK_KIND_WEIGHT = {
        "CONTAINER_STATE_MUTATION": 4,
        "RELEASE": 4,
        "STORAGE_RESIZE": 3,
        "ALLOCATION": 3,
        "MEMORY_COPY_OR_WRITE": 3,
        "MEMORY_READ_OR_INPUT": 2,
        "ARITHMETIC_OR_UPDATE": 1,
    }

    def _rank_fallback_facts(
        self,
        function_name: str,
        risk_facts: Sequence[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Rank uncovered high-risk facts and truncate to FALLBACK_MAX_FACTS.

        Priority signals (all static): operation-kind weight, reference to a
        function parameter (caller-influenced), external struct/member data, and
        non-constant subscript. Kept facts are re-sorted by source line so the
        prompt reads naturally; omitted facts are summarized by kind.
        """
        function_code = self.get_code(function_name) or ""
        try:
            params = self._function_param_names(function_code, function_name)
        except Exception:
            params = []
        param_pattern = (
            re.compile(r"\b(?:" + "|".join(re.escape(p) for p in params) + r")\b")
            if params else None
        )

        def score(fact: Dict[str, Any]) -> int:
            code = str(fact.get("code") or "")
            value = self._FALLBACK_KIND_WEIGHT.get(
                str(fact.get("operation_kind") or ""), 1
            )
            if param_pattern and param_pattern.search(code):
                value += 3
            if "->" in code or re.search(r"\b\w+\.\w+", code):
                value += 1
            if re.search(r"\[[^\]]*[A-Za-z_]", code):
                value += 1
            return value

        ranked = sorted(
            risk_facts,
            key=lambda fact: (-score(fact), _safe_int(fact.get("line"), 0)),
        )
        omitted: Dict[str, Any] = {}
        if FALLBACK_MAX_FACTS and len(ranked) > FALLBACK_MAX_FACTS:
            kept = ranked[:FALLBACK_MAX_FACTS]
            dropped = ranked[FALLBACK_MAX_FACTS:]
            by_kind: Dict[str, int] = defaultdict(int)
            for fact in dropped:
                by_kind[str(fact.get("operation_kind") or "UNKNOWN")] += 1
            omitted = {"total": len(dropped), "by_kind": dict(sorted(by_kind.items()))}
            ranked = kept
        ranked.sort(key=lambda fact: _safe_int(fact.get("line"), 0))
        return ranked, omitted

    def _make_fallback_path(
        self,
        function_name: str,
        risk_facts: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        ranked_facts, omitted = self._rank_fallback_facts(function_name, risk_facts)
        return [{
            "source_variable": "[Block Review]",
            "source_aliases": ["[Block Review]"],
            "source_identity": _stable_hash({"fallback": function_name}, 24),
            "source_type": "unknown_type",
            "taint_source": "High-risk operations not covered by precise extracted paths.",
            "source_from_function": "",
            "sink_operation": "[Block-Level Review]",
            "current_call_chain": [function_name],
            "control_checks": [],
            "sink_type": "Terminal (Fallback Review)",
            "sink_target_function": None,
            "context_mode": "block_fallback",
            "source_status": "not-identified",
            "path_kind": "block_fallback",
            "path_events": [dict(fact) for fact in ranked_facts],
            "fallback_omitted": omitted,
            "abstract_object": None,
            "sink_start_byte": -1,
        }]

    def _call_argument_provenance_facts(
        self,
        caller: str,
        callee: str,
        operation: str,
        parameter_index: int,
        start_byte: Any,
    ) -> List[Dict[str, Any]]:
        """Recover nearby caller-side definitions for one propagated argument.

        Parameter transfer alone records only the call expression. Retaining the
        nearest assignment and state check connects the callee formal parameter to
        the concrete value that reached it.
        """
        arguments = _call_arguments(operation, callee)
        if parameter_index >= len(arguments):
            return []
        argument = _normalize_space(arguments[parameter_index])
        if not re.fullmatch(
            r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*", argument
        ):
            return []

        function_code = self.get_code(caller) or ""
        encoded = function_code.encode("utf-8")
        offset = _safe_int(start_byte, -1)
        if 0 <= offset <= len(encoded):
            prefix = encoded[:offset].decode("utf-8", errors="ignore")
        else:
            call_index = function_code.find(operation)
            prefix = function_code[:call_index] if call_index >= 0 else function_code

        root_name = re.match(r"[A-Za-z_]\w*", argument).group(0)
        expression_parts = re.split(r"(->|\.)", argument)
        escaped_argument = "".join(
            r"\s*->\s*" if part == "->"
            else r"\s*\.\s*" if part == "."
            else re.escape(part)
            for part in expression_parts
        )
        escaped_root = re.escape(root_name)
        definitions: List[Tuple[int, str, str]] = []
        state_checks: List[Tuple[int, str, str]] = []
        for line_number, raw_line in enumerate(prefix.splitlines(), start=1):
            line = _normalize_space(raw_line)
            if not line or line.startswith(("//", "/*", "*")):
                continue
            if re.search(
                rf"(?<![.>\w]){escaped_argument}\s*=(?!=)", line
            ) or re.search(
                rf"\b(?:struct\s+\w+|[A-Za-z_]\w*(?:\s+|\s*\*+))+"
                rf"{escaped_root}\b(?:\s*=|\s*[;,])",
                line,
            ):
                definitions.append((line_number, line, "CALL_ARGUMENT_DEFINITION"))
            if re.search(
                rf"\b(?:if|while)\s*\([^)]*(?<![.>\w])"
                rf"{escaped_argument}(?!\w)",
                line,
            ):
                state_checks.append((line_number, line, "CALL_ARGUMENT_STATE_CHECK"))

        selected = definitions[-2:] + state_checks[-1:]
        selected.sort(key=lambda item: item[0])
        return [
            {
                "event_kind": event_kind,
                "code": code,
                "controls": [],
                "function": caller,
                "sink_type": "Transitive",
                "path_kind": "dataflow",
                "abstract_object": None,
                "sink_category": "CALL_ARGUMENT_PROVENANCE",
                "start_byte": -1,
                "parameter_index": parameter_index,
                "branch_signature": [],
            }
            for _, code, event_kind in selected
        ]

    def analyze(self) -> List[List[Dict[str, Any]]]:
        if not self.rooted_call_graphs:
            raise RuntimeError("Failed to generate rooted call graphs.")

        discovery_queue: deque[AnalysisTask] = deque()
        trace_queue: deque[AnalysisTask] = deque()
        queued_general: Set[str] = set()
        for root in self.rooted_call_graphs:
            discovery_queue.append(AnalysisTask(root, [root], False))
            queued_general.add(root)

        final_paths: List[List[Dict[str, Any]]] = []
        trace_seen: Set[Tuple[Any, ...]] = set()
        general_functions_analyzed: Set[str] = set()
        coverage_results_by_function: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        while trace_queue or discovery_queue:
            task = trace_queue.popleft() if trace_queue else discovery_queue.popleft()
            analysis_failed = False
            try:
                raw_results = self._analyze_function(task)
            except Exception as exc:
                analysis_failed = True
                error_message = (
                    f"static analysis failed for {task.function_name}, "
                    f"chain={' -> '.join(task.call_chain)}, param={task.parameter_index}: {exc}"
                )
                self.static_task_errors.append(error_message)
                print(f"  - Static analysis warning: {error_message}")
                raw_results = []

            coverage_results_by_function[task.function_name].extend(raw_results)
            if not task.is_transitive_analysis and len(task.call_chain) == 1:
                general_functions_analyzed.add(task.function_name)

            if analysis_failed and task.is_transitive_analysis and task.accumulated_path:
                previous = task.accumulated_path[-1]
                final_paths.append(task.accumulated_path + [{
                    "source_variable": previous.get("source_variable", "[unknown]"),
                    "source_aliases": _safe_list(previous.get("source_aliases")),
                    "source_identity": previous.get("source_identity", ""),
                    "source_type": previous.get("source_type", "unknown_type"),
                    "taint_source": previous.get("taint_source", ""),
                    "source_from_function": previous.get("source_from_function", ""),
                    "sink_operation": f"[Static analysis unavailable in {task.function_name}]",
                    "current_call_chain": list(task.call_chain),
                    "control_checks": [],
                    "source_status": previous.get("source_status", "not-identified"),
                    "context_mode": "path",
                    "sink_target_function": task.function_name,
                    "sink_type": "Terminal (Static Analysis Incomplete)",
                    "path_kind": previous.get("path_kind", "dataflow"),
                    "path_events": [],
                    "abstract_object": previous.get("abstract_object"),
                    "lifecycle_kind": previous.get("lifecycle_kind"),
                    "sink_category": "STATIC_ANALYSIS_INCOMPLETE",
                    "sink_start_byte": -1,
                    "path_step": len(task.accumulated_path),
                }])

            for raw_result in raw_results:
                aliases = sorted(set(str(x) for x in _safe_list(raw_result.get("source_variable")) if x))
                if not aliases:
                    continue
                taint_sources = [str(x) for x in _safe_list(raw_result.get("taint_source")) if x]
                source_functions = [str(x) for x in _safe_list(raw_result.get("source_from_function")) if x]
                path_kind = str(raw_result.get("path_kind", "dataflow"))
                abstract_object = raw_result.get("abstract_object")
                identity = _source_identity(
                    task.call_chain[0], aliases, taint_sources, source_functions,
                    path_kind, abstract_object, task.parameter_index,
                )

                for sink in _safe_list(raw_result.get("sinks")):
                    operation = sink.get("code")
                    if not operation:
                        continue
                    # Efficiency B1: drop locking/logging calls and bare
                    # self-checks. The segment survives only when lifecycle
                    # path_events still justify reviewing the path.
                    if _is_benign_sink_operation(operation, sink.get("category")) \
                            and not _safe_list(raw_result.get("lifecycle_events")):
                        continue
                    propagated_variable = _choose_alias_used(operation, aliases)
                    target_function = extract_function_name_from_string(operation)
                    is_internal_call = bool(target_function and target_function in self.defined_functions)
                    segment = {
                        "source_variable": propagated_variable,
                        "source_aliases": aliases,
                        "source_identity": identity,
                        "source_type": raw_result.get("source_type", "unknown_type"),
                        "taint_source": ", ".join(taint_sources),
                        "source_from_function": ", ".join(source_functions),
                        "sink_operation": operation,
                        "current_call_chain": list(task.call_chain),
                        "control_checks": sorted(set(_safe_list(sink.get("control_dependence")))),
                        # Non-guard note text (e.g. NULL-check observations on
                        # nullable paths) is stored in a separate field from guard
                        # conditions; it does not go into control_checks
                        "static_notes": _safe_list(sink.get("static_notes")),
                        # [SHADOW] Structured guard/event facts: purely additive
                        # fields, excluded from signature/grouping/prompt/verdict logic
                        "guard_facts": _safe_list(sink.get("guard_facts")),
                        "event_sequence": _safe_list(sink.get("event_sequence")),
                        "source_status": "precise" if taint_sources else "not-identified",
                        "context_mode": "path",
                        "sink_target_function": target_function,
                        "sink_type": "Transitive" if is_internal_call else "Terminal",
                        "path_kind": path_kind,
                        "path_events": _safe_list(raw_result.get("lifecycle_events")),
                        "abstract_object": abstract_object,
                        "lifecycle_kind": raw_result.get("lifecycle_kind"),
                        "sink_category": sink.get("category", ""),
                        "object_identity": sink.get("object_identity"),
                        "evidence_status": sink.get("evidence_status"),
                        "sink_start_byte": _safe_int(sink.get("start_byte"), -1),
                        "branch_signature": _safe_list(sink.get("branch_signature")),
                        "object_id": sink.get("object_id", abstract_object),
                        "path_step": len(task.accumulated_path),
                    }

                    if is_internal_call:
                        current_depth = len(task.call_chain)
                        trace_depth_budget = self.trace_depth_budget(task.call_chain[0])
                        depth_allowed = (
                            trace_depth_budget < 0
                            or current_depth < trace_depth_budget
                        )
                        recursive = target_function in task.call_chain
                        positions = get_argument_positions(operation, target_function, aliases)
                        if depth_allowed and not recursive and positions:
                            for parameter_index in positions:
                                edge_signature = _call_edge_identity(
                                    task.call_chain[-1],
                                    target_function,
                                    sink.get("start_byte", -1),
                                    operation,
                                    sink.get("control_dependence"),
                                )
                                edge_segment = dict(segment)
                                edge_segment["call_edge_signature"] = edge_signature
                                edge_segment["parameter_index"] = parameter_index
                                edge_segment["call_argument_provenance"] = (
                                    self._call_argument_provenance_facts(
                                        task.call_chain[-1],
                                        target_function,
                                        operation,
                                        parameter_index,
                                        sink.get("start_byte", -1),
                                    )
                                )
                                variant_signature = _stable_hash({
                                    "controls": sorted(set(_safe_list(sink.get("control_dependence")))),
                                    "branch_signature": sorted(_safe_list(sink.get("branch_signature"))),
                                }, 20)
                                trace_key = (
                                    target_function,
                                    tuple(task.call_chain + [target_function]),
                                    parameter_index,
                                    identity,
                                    edge_signature,
                                    variant_signature,
                                )
                                if trace_key in trace_seen:
                                    continue
                                trace_seen.add(trace_key)
                                trace_queue.append(AnalysisTask(
                                    function_name=target_function,
                                    call_chain=task.call_chain + [target_function],
                                    is_transitive_analysis=True,
                                    accumulated_path=task.accumulated_path + [edge_segment],
                                    parameter_index=parameter_index,
                                    path_history_context=(
                                        f"Source aliases {aliases} flow from {task.call_chain[-1]} "
                                        f"to {target_function} argument {parameter_index} via {operation}."
                                    ),
                                    abstract_object_hint=(
                                        abstract_object
                                        or task.abstract_object_hint
                                    ),
                                ))
                            continue

                        if recursive:
                            segment["sink_type"] = "Terminal (Stopped Recursive Call)"
                        elif not depth_allowed:
                            segment["sink_type"] = "Terminal (Depth-Limited)"
                        elif not positions:
                            # Preserve evidence instead of silently dropping it.
                            segment["sink_type"] = "Terminal (Unresolved Parameter Propagation)"
                            segment["call_edge_signature"] = _call_edge_identity(
                                task.call_chain[-1],
                                target_function,
                                sink.get("start_byte", -1),
                                operation,
                                sink.get("control_dependence"),
                            )

                    final_paths.append(task.accumulated_path + [segment])

            # Preserve the original coverage strategy: every internal function is also
            # locally analyzed once as a possible independent source root.
            for callee in self.callee_index.get(task.function_name, []):
                if callee not in queued_general:
                    queued_general.add(callee)
                    discovery_queue.append(AnalysisTask(callee, [callee], False))

        # Fallback is decided only after all local and transitive analyses finish.
        # This prevents a local root from scheduling block review for operations
        # already covered by a precise upstream propagation path.
        for function_name in sorted(general_functions_analyzed):
            coverage_results = self._dedup_raw_results(
                coverage_results_by_function.get(function_name, [])
            )
            risk_facts = self._fallback_risk_facts(function_name, coverage_results)
            if not risk_facts:
                continue
            fallback_path = self._make_fallback_path(function_name, risk_facts)
            final_paths.append(fallback_path)
            shown_events = _safe_list(fallback_path[0].get("path_events"))
            omitted = fallback_path[0].get("fallback_omitted") or {}
            self.fallback_task_count += 1
            self.fallback_operation_count += len(shown_events)
            self.fallback_omitted_count += _safe_int(omitted.get("total"), 0)

        return self._dedup_final_paths(self._cap_nullable_origin_paths(final_paths))

    @staticmethod
    def _cap_nullable_origin_paths(
        paths: Sequence[List[Dict[str, Any]]],
    ) -> List[List[Dict[str, Any]]]:
        """Optional file-level budget for nullable-origin paths (low-budget mode).

        Disabled by default (MAX_NULLABLE_ORIGIN_PATHS_PER_FILE == 0): the
        budget-aware pre-aggregation keeps final LLM task counts flat even with
        all nullable paths retained, so truncation only costs recall. When a
        positive cap is configured, rank nullable paths — IS_ERR-insufficiency
        evidence first, then shorter chains — and keep the top slice. Other
        path kinds are untouched.
        """
        if MAX_NULLABLE_ORIGIN_PATHS_PER_FILE <= 0:
            return list(paths)
        nullable = [
            path for path in paths
            if path and path[0].get("path_kind") == "nullable_origin"
        ]
        if len(nullable) <= MAX_NULLABLE_ORIGIN_PATHS_PER_FILE:
            return paths

        def priority(path: List[Dict[str, Any]]) -> Tuple[Any, ...]:
            has_insufficiency = any(
                "does not exclude NULL" in str(note)
                for segment in path
                for note in _safe_list(segment.get("static_notes"))
            )
            return (not has_insufficiency, len(path))

        keep = {
            id(path)
            for path in sorted(nullable, key=priority)[:MAX_NULLABLE_ORIGIN_PATHS_PER_FILE]
        }
        kept: List[List[Dict[str, Any]]] = []
        dropped = 0
        for path in paths:
            if (
                path
                and path[0].get("path_kind") == "nullable_origin"
                and id(path) not in keep
            ):
                dropped += 1
                continue
            kept.append(path)
        print(
            f"  - Nullable-origin path budget: {len(nullable)} -> "
            f"{len(nullable) - dropped} path(s) "
            f"(cap {MAX_NULLABLE_ORIGIN_PATHS_PER_FILE})."
        )
        return kept

    @staticmethod
    def _dedup_final_paths(paths: Sequence[List[Dict[str, Any]]]) -> List[List[Dict[str, Any]]]:
        deduped: List[List[Dict[str, Any]]] = []
        seen: Set[str] = set()
        for path in paths:
            if not path:
                continue
            signature = []
            for segment in path:
                signature.append({
                    "source_identity": segment.get("source_identity"),
                    "chain": segment.get("current_call_chain"),
                    "operation": _normalize_code(segment.get("sink_operation")),
                    "sink_type": segment.get("sink_type"),
                    "controls": sorted(_safe_list(segment.get("control_checks"))),
                    "path_kind": segment.get("path_kind", "dataflow"),
                    "abstract_object": segment.get("abstract_object"),
                    "call_edge_signature": segment.get("call_edge_signature", ""),
                    "parameter_index": segment.get("parameter_index"),
                    "call_argument_provenance": [
                        (
                            fact.get("event_kind"),
                            _normalize_code(fact.get("code")),
                            fact.get("parameter_index"),
                        )
                        for fact in _safe_list(segment.get("call_argument_provenance"))
                    ],
                    "events": [
                        (
                            event.get("event_kind"),
                            _normalize_code(event.get("code")),
                            event.get("statement_index"),
                        )
                        for event in _safe_list(segment.get("path_events"))
                    ],
                })
            marker = json.dumps(signature, sort_keys=True, ensure_ascii=False, default=str)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(path)
        return deduped



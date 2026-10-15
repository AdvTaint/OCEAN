"""Code context construction and caching."""

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
    extract_relevant_declarations,
    extract_relevant_macro_definitions,
)

from .config import (
    CONTEXT_CALLEE_DEPTH,
    CONTEXT_CALLER_DEPTH,
    EVIDENCE_ONLY_CODE_CONTEXT_CHARS,
    FOCUSED_CODE_CONTEXT_CHARS,
    MAX_CODE_CONTEXT_CHARS,
    MAX_DECLARATION_CONTEXT_CHARS,
    MAX_MACRO_CONTEXT_CHARS,
    MINIMAL_CODE_CONTEXT_CHARS,
    MIN_SUPPORT_FUNCTION_CHARS,
)
from .engine import (
    StaticAnalysisEngine,
)
from .structures import (
    MultiSourcePathTask,
)
from .textutil import (
    _source_sink_marker,
    _dedup_preserve_order,
    _normalize_space,
    _safe_list,
    _stable_hash,
)
from .tpt import (
    _all_task_facts,
    _all_task_sinks,
    _task_path_functions,
    _task_path_signature,
    _task_source_defining_funcs,
)


class ContextBuilder:
    def __init__(self, engine: StaticAnalysisEngine):
        self.engine = engine
        self.cache: Dict[Tuple[Any, ...], Tuple[str, str, Tuple[str, ...]]] = {}
        # Mandatory path functions dropped by the most recent build() call.
        # _apply_prompt_profile treats any drop as an infeasible profile.
        self.last_dropped_mandatory: List[str] = []
        self.last_degraded_mandatory: List[str] = []
        # Budget fitting evaluates multiple profiles for the same evidence.
        # Cache macro scans independently from the final context profile.
        self.macro_cache: Dict[Tuple[str, int], Dict[str, str]] = {}

    def _neighbors(self, target: str, caller_depth: int, callee_depth: int) -> List[str]:
        result: List[str] = []
        seen = {target}

        if caller_depth != 0:
            queue: deque[Tuple[str, int]] = deque([(target, 0)])
            while queue:
                current, depth = queue.popleft()
                if caller_depth >= 0 and depth >= caller_depth:
                    continue
                for caller in self.engine.caller_index.get(current, []):
                    if caller in seen:
                        continue
                    seen.add(caller)
                    result.append(caller)
                    queue.append((caller, depth + 1))

        if callee_depth != 0:
            queue = deque([(target, 0)])
            while queue:
                current, depth = queue.popleft()
                if callee_depth >= 0 and depth >= callee_depth:
                    continue
                for callee in self.engine.callee_index.get(current, []):
                    if callee in seen:
                        continue
                    seen.add(callee)
                    result.append(callee)
                    queue.append((callee, depth + 1))
        return result

    @staticmethod
    def _compact_support_code(code: str, available_chars: int) -> str:
        if len(code) <= available_chars:
            return code
        if available_chars <= 500:
            return ""
        half = max(200, (available_chars - 80) // 2)
        return code[:half] + "\n/* ... support function middle omitted ... */\n" + code[-half:]

    @staticmethod
    def _mode_code_budget(mode: str) -> int:
        if mode == "focused":
            return FOCUSED_CODE_CONTEXT_CHARS
        if mode in {"minimal", "evidence_only"}:
            return (
                EVIDENCE_ONLY_CODE_CONTEXT_CHARS
                if mode == "evidence_only"
                else MINIMAL_CODE_CONTEXT_CHARS
            )
        return MAX_CODE_CONTEXT_CHARS

    @staticmethod
    def _mode_macro_budget(mode: str) -> int:
        if mode == "focused":
            return min(MAX_MACRO_CONTEXT_CHARS, 8192)
        if mode == "minimal":
            return min(MAX_MACRO_CONTEXT_CHARS, 4096)
        if mode == "evidence_only":
            return min(MAX_MACRO_CONTEXT_CHARS, 2048)
        return MAX_MACRO_CONTEXT_CHARS

    @staticmethod
    def _sink_operations_by_function(task: MultiSourcePathTask) -> Dict[str, List[str]]:
        operations: Dict[str, List[str]] = defaultdict(list)
        for subpath in task.source_subpaths:
            for sink in subpath.sinks:
                function_name = str(sink.get("function") or task.target_function)
                if sink.get("operation"):
                    operations[function_name].append(str(sink["operation"]))
        return operations

    @staticmethod
    def _evidence_by_function(task: MultiSourcePathTask) -> Dict[str, List[str]]:
        evidence: Dict[str, List[str]] = defaultdict(list)
        for subpath in task.source_subpaths:
            for fact in subpath.facts:
                function_name = str(fact.get("function") or task.target_function)
                if fact.get("code"):
                    evidence[function_name].append(str(fact["code"]))
                evidence[function_name].extend(str(item) for item in _safe_list(fact.get("controls")) if item)
            for sink in subpath.sinks:
                function_name = str(sink.get("function") or task.target_function)
                if sink.get("operation"):
                    evidence[function_name].append(str(sink["operation"]))
                evidence[function_name].extend(str(item) for item in _safe_list(sink.get("controls")) if item)
        return {name: _dedup_preserve_order(items) for name, items in evidence.items()}

    @staticmethod
    def _signature_line_indices(lines: Sequence[str]) -> Set[int]:
        selected: Set[int] = set()
        for index, line in enumerate(lines[:20]):
            selected.add(index)
            if "{" in line:
                break
        if lines:
            selected.update(range(max(0, len(lines) - 3), len(lines)))
        return selected

    @staticmethod
    def _evidence_line_indices(lines: Sequence[str], evidence_items: Sequence[str]) -> Set[int]:
        selected: Set[int] = set()
        normalized_lines = [_normalize_space(line) for line in lines]
        common_tokens = {
            "if", "else", "for", "while", "return", "sizeof", "const", "struct",
            "int", "char", "void", "unsigned", "signed", "long", "short",
        }
        for evidence in evidence_items:
            compact = _normalize_space(evidence)
            if not compact:
                continue
            direct_hits = [
                index for index, line in enumerate(normalized_lines)
                if compact in line or (line and line in compact and len(line) >= 12)
            ]
            if direct_hits:
                selected.update(direct_hits[:4])
                continue
            identifiers = [
                token for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", compact)
                if token not in common_tokens and len(token) >= 3
            ]
            identifiers = sorted(set(identifiers), key=len, reverse=True)[:6]
            if not identifiers:
                continue
            scored: List[Tuple[int, int]] = []
            for index, line in enumerate(lines):
                score = sum(1 for token in identifiers if re.search(rf"\b{re.escape(token)}\b", line))
                if score:
                    scored.append((score, index))
            scored.sort(key=lambda item: (-item[0], item[1]))
            selected.update(index for _, index in scored[:3])
        return selected

    @staticmethod
    def _lifecycle_counterevidence_line_indices(
        lines: Sequence[str], evidence_items: Sequence[str]
    ) -> Set[int]:
        """Preserve refresh evidence around backward lifecycle transitions.

        Compact contexts often retain both releases but omit the output-parameter
        assignment reached through a backward goto. That omission changes object
        identity and can create a spurious double-free/UAF path.
        """
        release_apis = ("free", "kfree", "xfree", "g_free", "delete", "delete[]")
        variables: Set[str] = set()
        for evidence in evidence_items:
            for api_name in release_apis:
                match = re.search(
                    rf"\b{re.escape(api_name)}\s*\(\s*([A-Za-z_]\w*)\s*\)",
                    str(evidence),
                )
                if match:
                    variables.add(match.group(1))

        selected: Set[int] = set()
        if not variables:
            return selected

        label_indices: Dict[str, int] = {}
        for index, line in enumerate(lines):
            label_match = re.match(
                r"\s*([A-Za-z_]\w*)\s*:\s*(?:/\*.*\*/\s*)?$", line
            )
            if label_match:
                label_indices[label_match.group(1)] = index

        for variable in variables:
            release_pattern = re.compile(
                rf"\b(?:free|kfree|xfree|g_free|delete(?:\s*\[\])?)\s*\(\s*"
                rf"{re.escape(variable)}\s*\)"
            )
            refresh_pattern = re.compile(
                rf"(?:&\s*{re.escape(variable)}\b|\b{re.escape(variable)}\s*=)"
            )
            release_indices = [
                index for index, line in enumerate(lines) if release_pattern.search(line)
            ]
            for release_index in release_indices:
                for goto_index in range(
                    release_index, min(len(lines), release_index + 6)
                ):
                    goto_match = re.search(
                        r"\bgoto\s+([A-Za-z_]\w*)\s*;", lines[goto_index]
                    )
                    if goto_match is None:
                        continue
                    label_index = label_indices.get(goto_match.group(1))
                    if label_index is None or label_index >= release_index:
                        continue
                    refresh_indices = [
                        index
                        for index in range(label_index, release_index)
                        if refresh_pattern.search(lines[index])
                    ]
                    if refresh_indices:
                        selected.update({label_index, goto_index, release_index})
                        selected.update(refresh_indices)
        return selected

    @staticmethod
    def _pinned_sink_line_indices(lines: Sequence[str], sink_operations: Sequence[str]) -> Set[int]:
        """Locate every selected sink operation line by its first normalized line.

        Sink lines are pinned unconditionally: they must survive even when the
        heuristic evidence text-matching above fails to find them.
        """
        selected: Set[int] = set()
        normalized_lines = [_normalize_space(line) for line in lines]
        for operation in sink_operations:
            text = str(operation or "").strip()
            if not text:
                continue
            first_line = _normalize_space(text.splitlines()[0])
            if not first_line:
                continue
            for index, line in enumerate(normalized_lines):
                if first_line in line or (line and line in first_line and len(line) >= 8):
                    selected.add(index)
        return selected

    @classmethod
    def _focused_code(cls, code: str, evidence_items: Sequence[str], available_chars: int, mode: str, pinned_sink_operations: Sequence[str] = ()) -> str:
        if len(code) <= available_chars and mode == "focused":
            return code
        lines = code.splitlines()
        if not lines or available_chars <= 0:
            return ""
        selected = cls._signature_line_indices(lines)
        evidence_lines = cls._evidence_line_indices(lines, evidence_items)
        counterevidence_lines = cls._lifecycle_counterevidence_line_indices(
            lines, evidence_items
        )
        radius = 4 if mode == "focused" else (2 if mode == "minimal" else 1)
        for index in evidence_lines | counterevidence_lines:
            selected.update(
                range(max(0, index - radius), min(len(lines), index + radius + 1))
            )
        # Sink-line pinning: radius >= 3, added before any budget compaction.
        pinned_lines = cls._pinned_sink_line_indices(lines, pinned_sink_operations)
        for index in pinned_lines:
            selected.update(
                range(max(0, index - 3), min(len(lines), index + 4))
            )
        ordered = sorted(selected)
        if not ordered:
            return cls._compact_support_code(code, available_chars)

        blocks: List[str] = []
        block_start = previous = ordered[0]
        for index in ordered[1:] + [None]:
            if index is not None and index == previous + 1:
                previous = index
                continue
            excerpt = "\n".join(lines[block_start:previous + 1])
            blocks.append(f"/* lines {block_start + 1}-{previous + 1} */\n{excerpt}")
            if index is not None:
                block_start = previous = index
        result = "\n/* ... unrelated lines omitted ... */\n".join(blocks)
        if len(result) <= available_chars:
            return result

        # A second head/tail compaction must not discard explicitly selected
        # lifecycle blockers or pinned sink lines from a large function.
        critical_lines = counterevidence_lines | pinned_lines
        critical_excerpt = ""
        if critical_lines:
            critical_excerpt = (
                "\n/* mandatory lifecycle/control/sink evidence */\n"
                + "\n".join(lines[index] for index in sorted(critical_lines))
                + "\n"
            )
        if len(critical_excerpt) >= available_chars:
            return critical_excerpt[:available_chars]
        compact_budget = available_chars - len(critical_excerpt)
        compact = cls._compact_support_code(result, compact_budget)
        return compact + critical_excerpt

    def build(
        self,
        task: MultiSourcePathTask,
        caller_depth: Optional[int] = None,
        callee_depth: Optional[int] = None,
        code_mode: str = "full",
    ) -> Tuple[str, str]:
        caller_depth = CONTEXT_CALLER_DEPTH if caller_depth is None else caller_depth
        callee_depth = CONTEXT_CALLEE_DEPTH if callee_depth is None else callee_depth
        if code_mode not in {"full", "focused", "minimal", "evidence_only"}:
            raise ValueError(f"Unknown code context mode: {code_mode}")

        all_facts = _all_task_facts(task)
        all_sinks = _all_task_sinks(task)
        relevant_text = "\n".join(
            [str(fact.get("code") or "") for fact in all_facts]
            + [str(sink.get("operation") or "") for sink in all_sinks]
        )
        macro_budget = self._mode_macro_budget(code_mode)
        macro_key = (_stable_hash(relevant_text, 32), macro_budget)
        if macro_key in self.macro_cache:
            macro_map = self.macro_cache[macro_key]
        else:
            try:
                macro_map = extract_relevant_macro_definitions(
                    self.engine.file_path,
                    relevant_text,
                    max_definitions=None,
                    max_chars=macro_budget,
                )
            except Exception as exc:
                print(f"  - Macro context warning for {task.task_id}: {exc}")
                macro_map = {}
            self.macro_cache[macro_key] = macro_map
        macro_context = "\n\n".join(macro_map.values())
        macro_signature = tuple(macro_map.keys())
        source_defining_funcs = _task_source_defining_funcs(task)
        path_functions = _task_path_functions(task)
        path_signature = _task_path_signature(task)
        sink_signature = tuple(sorted(
            _source_sink_marker(sp, sink)
            for sp in task.source_subpaths
            for sink in sp.sinks
        ))
        declaration_seed_functions = _dedup_preserve_order(
            [task.target_function] + source_defining_funcs + path_functions
        )
        declaration_seed = relevant_text + "\n" + "\n".join(
            self.engine.get_code(function_name) or ""
            for function_name in declaration_seed_functions
        )
        declaration_budget = min(
            MAX_DECLARATION_CONTEXT_CHARS,
            max(0, self._mode_code_budget(code_mode) // 4),
        )
        try:
            declaration_map = extract_relevant_declarations(
                self.engine.file_path,
                declaration_seed,
                max_chars=declaration_budget,
            )
        except Exception as exc:
            print(f"  - Declaration context warning for {task.task_id}: {exc}")
            declaration_map = {}
        declaration_context = "\n\n".join(declaration_map.values())
        declaration_signature = tuple(declaration_map.keys())
        cache_key = (
            path_signature,
            task.target_function,
            tuple(source_defining_funcs),
            sink_signature,
            macro_signature,
            declaration_signature,
            self._mode_code_budget(code_mode),
            caller_depth,
            callee_depth,
            code_mode,
        )
        if cache_key in self.cache:
            cached_entry = self.cache[cache_key]
            if len(cached_entry) == 4:
                cached_context, cached_macros, cached_dropped, cached_degraded = cached_entry
            else:
                cached_context, cached_macros, cached_dropped = cached_entry
                cached_degraded = ()
            self.last_dropped_mandatory = list(cached_dropped)
            self.last_degraded_mandatory = list(cached_degraded)
            return cached_context, cached_macros

        ordered_functions: List[str] = []
        for name in [task.target_function] + source_defining_funcs + path_functions:
            if name and name not in ordered_functions:
                ordered_functions.append(name)
        for name in self._neighbors(task.target_function, caller_depth, callee_depth):
            if name not in ordered_functions:
                ordered_functions.append(name)

        mandatory = {task.target_function, *source_defining_funcs, *path_functions}
        evidence_map = self._evidence_by_function(task)
        sink_operations_map = self._sink_operations_by_function(task)
        code_budget = self._mode_code_budget(code_mode)
        blocks: List[str] = []
        used = 0
        dropped_mandatory: List[str] = []
        degraded_mandatory: List[str] = []
        if declaration_context:
            declaration_block = (
                "// Relevant Type and Global Declarations\n"
                + declaration_context
                + "\n\n"
            )
            if len(declaration_block) <= code_budget:
                blocks.append(declaration_block)
                used += len(declaration_block)

        function_entries = [
            (function_name, self.engine.get_code(function_name) or "")
            for function_name in ordered_functions
        ]
        function_entries = [entry for entry in function_entries if entry[1]]
        mandatory_entries = [
            entry for entry in function_entries if entry[0] in mandatory
        ]
        supporting_entries = [
            entry for entry in function_entries if entry[0] not in mandatory
        ]

        def role_for(function_name: str) -> str:
            if function_name == task.target_function:
                return "Analysis Target Function"
            if function_name in source_defining_funcs:
                return "Source Definition Function"
            if function_name in path_functions:
                return "Exact Call-Path Function"
            return "Supporting Function"

        mandatory_full_size = sum(
            len(code) + len(f"// {role_for(function_name)}: {function_name}\n") + 2
            for function_name, code in mandatory_entries
        )
        # Path functions keep their complete bodies under "full" AND "focused"
        # modes whenever the mandatory set fits: snippet windows (radius <= 4
        # around evidence lines) systematically hide the exact defensive logic
        # (init-time validation, patch-added checks) that refutes hypotheses on
        # patched code. Degrading a path function marks the profile infeasible
        # so the budget cascade escalates to operation/path splitting instead.
        keep_full_mandatory = code_mode in ("full", "focused") and mandatory_full_size <= code_budget

        # Allocate a share to every mandatory path function before adding graph
        # neighbors. A large target function must never consume the budget and
        # silently remove a later caller/callee from the exact path.
        for index, (function_name, code) in enumerate(mandatory_entries):
            header = f"// {role_for(function_name)}: {function_name}\n"
            remaining_functions = len(mandatory_entries) - index
            remaining_budget = code_budget - used
            content_budget = max(
                0,
                remaining_budget // max(1, remaining_functions) - len(header) - 2,
            )
            if content_budget <= 0:
                # Never silently drop a mandatory path function: the profile is
                # infeasible and the budget cascade must move to the next level.
                dropped_mandatory.append(function_name)
                continue
            evidence_items = evidence_map.get(function_name, [])
            if keep_full_mandatory:
                selected = code
            else:
                compact_mode = code_mode if code_mode != "full" else "focused"
                selected = self._focused_code(
                    code,
                    evidence_items,
                    content_budget,
                    compact_mode,
                    pinned_sink_operations=sink_operations_map.get(function_name, []),
                )
            if not selected:
                dropped_mandatory.append(function_name)
                continue
            if selected != code:
                degraded_mandatory.append(function_name)
            block = header + selected + "\n\n"
            if used + len(block) > code_budget:
                dropped_mandatory.append(function_name)
                continue
            blocks.append(block)
            used += len(block)

        for function_name, code in supporting_entries:
            header = f"// Supporting Function: {function_name}\n"
            remaining = code_budget - used - len(header) - 2
            if remaining <= 0:
                break
            evidence_items = evidence_map.get(function_name, [])
            if code_mode == "full":
                selected = self._compact_support_code(
                    code, min(remaining, MIN_SUPPORT_FUNCTION_CHARS)
                )
            else:
                selected = self._focused_code(
                    code,
                    evidence_items,
                    min(remaining, max(1500, MIN_SUPPORT_FUNCTION_CHARS // 2)),
                    code_mode,
                    pinned_sink_operations=sink_operations_map.get(function_name, []),
                )
            if not selected:
                continue
            block = header + selected + "\n\n"
            if used + len(block) > code_budget:
                continue
            blocks.append(block)
            used += len(block)

        code_context = "".join(blocks)
        self.last_dropped_mandatory = list(dropped_mandatory)
        self.last_degraded_mandatory = list(degraded_mandatory)
        self.cache[cache_key] = (
            code_context,
            macro_context,
            tuple(dropped_mandatory),
            tuple(degraded_mandatory),
        )
        return code_context, macro_context



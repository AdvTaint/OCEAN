"""Deterministic evidence retrieval: entity conditions, carrier extent, lifetime links, VEC counter-evidence."""

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
    from .engine import StaticAnalysisEngine

from .vec_retrieval import (
    applicable_families as _vec_applicable_families,
    find_producer_null_checks as _vec_find_producer_null_checks,
    render_grouped_items as _vec_render_grouped,
    retrieve_counterevidence as _vec_retrieve,
    scan_function as _vec_scan_function,
    select_new_items as _vec_select_new,
    sink_producer_calls as _vec_sink_producer_calls,
)

from .config import (
    CARRIER_EXTENT,
    CARRIER_EXTENT_MAX_PER_SINK,
    CARRIER_EXTENT_MAX_RENDER,
    ENTITY_ALLOCATIONS,
    ENTITY_ALLOCATIONS_FILEWIDE,
    ENTITY_ALLOCATIONS_MAX_PER_SINK,
    ENTITY_ALLOCATIONS_MAX_RENDER,
    ENTITY_CONDITIONS,
    ENTITY_CONDITIONS_CALLERS,
    ENTITY_CONDITIONS_FIELD_FILEWIDE,
    ENTITY_CONDITIONS_MAX_PER_SINK,
    ENTITY_CONDITIONS_MAX_RENDER,
    GUARDFACT_PROMPT,
    LIFETIME_LINKS,
    LIFETIME_LINKS_MAX_PER_FILE,
    LIFETIME_LINKS_MAX_PER_TASK,
    LIFETIME_LINKS_MAX_SITES,
    VEC_COUNTER_EVIDENCE,
    VEC_FAMILIES,
    VEC_MAX_ITEMS,
    VEC_NULLABILITY_MAX_SITES,
    VEC_NULLABILITY_SIGNALS,
)
from .structures import (
    MultiSourcePathTask,
    SourceSubpath,
)
from .textutil import (
    _guard_fact_annotation,
    _prompt_facts_for_subpath,
    _split_call_arguments,
    _dedup_preserve_order,
    _normalize_space,
    _safe_list,
)
from .tpt import (
    _task_path_functions,
)


_ENTITY_COND_START = re.compile(r"^\s*(?:else\s+)?(?:if|while)\s*\(")


_ENTITY_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


_BRACKET_SEGMENT_RE = re.compile(r"\[[^\]]*\]")


_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "NULL", "true", "false",
})


_ENTITY_DISPLAY_NOISE = frozenset({"aliases", "more", "object", "unknown", "source"})


def _entity_tokens_from_text(text: str) -> List[str]:
    """Identifier tokens minus C keywords. Single-character variables (i, p)
    are kept: they are key entities in real cases."""
    return [
        token for token in _ENTITY_TOKEN_RE.findall(text or "")
        if token not in _C_KEYWORDS
    ]


def _source_display_entities(display: str) -> List[str]:
    """Recover source variable name + aliases from the `_source_display` string
    (`args (aliases: stack, temp)` / `name @ object` / single name)."""
    head = str(display or "").split(" @ ", 1)[0]
    head = _BRACKET_SEGMENT_RE.sub(" ", head)
    return [
        token for token in _entity_tokens_from_text(head)
        if token not in _ENTITY_DISPLAY_NOISE
    ]


def _extract_text_entity_conditions(
    code: str,
    entities: Sequence[str],
    cap: int = 40,
) -> List[str]:
    """Pure-text fallback indexer: if/while conditions in `code` that mention
    any entity (word-boundary match). Multi-line conditions are joined through
    parenthesis balancing. Deterministic and bounded by `cap`."""
    if not entities or not code:
        return []
    pats = [re.compile(r"\b" + re.escape(e) + r"\b") for e in entities if e]
    if not pats:
        return []
    results: List[str] = []
    lines = code.splitlines()
    i = 0
    while i < len(lines) and len(results) < cap:
        line = lines[i]
        if _ENTITY_COND_START.match(line):
            start = line.index("(")
            depth = 0
            text_parts: List[str] = []
            j = i
            done = False
            while j < len(lines) and not done:
                seg = lines[j]
                k = start if j == i else 0
                while k < len(seg):
                    ch = seg[k]
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            text_parts.append(seg[start if j == i else 0:k + 1])
                            done = True
                            break
                    k += 1
                if not done:
                    text_parts.append(seg[start if j == i else 0:])
                    j += 1
            cond = _normalize_space(" ".join(text_parts))
            if any(pat.search(cond) for pat in pats):
                results.append(cond)
            i = j + 1
        else:
            i += 1
    return results


def _strip_enclosing_parens(text: str) -> str:
    """Strip one layer of parens only when they enclose the whole string, so
    `(a > b)` compares equal to pool entries stored as `a > b`."""
    if not (text.startswith("(") and text.endswith(")")):
        return text
    depth = 0
    for index, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return text
    return text[1:-1].strip() if depth == 0 else text


def _sink_entity_set(subpath: SourceSubpath, sink: Dict[str, Any]) -> List[str]:
    """Entity set shared by the condition and allocation indexes: identifiers
    from the sink operation text plus the source variable name and aliases."""
    return _dedup_preserve_order(
        _entity_tokens_from_text(str(sink.get("operation") or ""))
        + _source_display_entities(getattr(subpath, "source_display", ""))
    )


_ENTITY_FIELD_RE = re.compile(r"(?:->|\.)\s*([A-Za-z_]\w*)")


def _sink_field_entities(sink: Dict[str, Any]) -> List[str]:
    """Struct-field components of the sink operation (identifiers after `->`
    or `.`). Field capacity/allocation statements legitimately live in init
    functions far from any evidence path, so they justify a file-wide scan;
    plain variables remain path-scoped."""
    operation = str(sink.get("operation") or "")
    return _dedup_preserve_order(
        name for name in _ENTITY_FIELD_RE.findall(operation)
        if name not in _C_KEYWORDS
    )


_CARRIER_RECEIVER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)")


_CARRIER_EXTENT_RVALUE_RE = re.compile(r"alloc|clone|duplicate|reserve", re.I)


def _carrier_extent_for_sink(
    task: MultiSourcePathTask,
    sink: Dict[str, Any],
    engine: "StaticAnalysisEngine",
    guard_texts: Set[str],
    code_texts: Set[str],
) -> List[str]:
    """Extent-establishing statements for carrier objects behind sink values.

    A pointer/length sink argument is often derived from a carrier object
    (`privacyHeader = hdr->PrivacyHeader(msgCopy->Start())`); the statements
    that establish the carrier's extent (clone/alloc assignments, length/size
    accessor calls such as `msg->DataLength()`) legitimately live in callers
    or init functions that the path-scoped context never shows, leaving the
    verifier no way to resolve a capacity question. Carriers are discovered
    from the visible definition of each sink value variable, then scanned
    file-wide; an assignment like `msgCopy = msg.CloneData()` contributes one
    follow-up hop onto its rvalue receivers. Deterministic, bounded, and
    never used for filtering."""
    operation = str(sink.get("operation") or "")
    if not operation:
        return []
    call_names = {
        match.group(1)
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", operation)
    }
    value_vars = [
        token for token in _entity_tokens_from_text(operation)
        if token not in call_names and token not in _sink_field_entities(sink)
    ]
    if not value_vars:
        return []
    sink_func = str(sink.get("function") or task.target_function)
    try:
        sink_code = engine.get_code(sink_func) or ""
    except Exception:
        sink_code = ""
    if not sink_code:
        return []

    carriers: List[str] = []
    for var in value_vars:
        for match in re.finditer(rf"\b{re.escape(var)}\b\s*=\s*([^;]+);", sink_code):
            for receiver in _CARRIER_RECEIVER_RE.findall(match.group(1)):
                if receiver != var and receiver not in _C_KEYWORDS:
                    carriers.append(receiver)
    carriers = _dedup_preserve_order(carriers)
    if not carriers:
        return []

    candidates: List[Tuple[str, str, int, int]] = []  # (func, stmt, kind, hop)
    seen: Set[str] = set()
    active = carriers
    hop = 0
    while active and hop < 2:
        hop += 1
        next_carriers: List[str] = []
        carrier_pats = [
            (carrier, re.compile(rf"\b{re.escape(carrier)}\b")) for carrier in active
        ]
        for func_name in _safe_list(getattr(engine, "defined_function_names", [])):
            func_name = str(func_name)
            try:
                code = engine.get_code(func_name) or ""
            except Exception:
                continue
            lines = code.splitlines()
            for index, line in enumerate(lines):
                if line.strip().startswith("//"):
                    continue
                raw_parts = [line.strip()]
                if ";" not in line:
                    for follow in lines[index + 1:index + 3]:
                        raw_parts.append(follow.strip())
                        if ";" in follow:
                            break
                raw = " ".join(raw_parts)
                if ";" not in raw:
                    # Incomplete join (e.g., macro invocation): skip.
                    continue
                stmt = _normalize_space(raw).rstrip(";").strip()
                if not stmt:
                    continue
                # The sink function body is already visible in context; only
                # out-of-context statements add information.
                if func_name == sink_func or stmt in sink_code:
                    continue
                # Drop comment/brace/attribute remnants from statement joining.
                stmt = re.sub(r"//.*", "", stmt)
                stmt = re.sub(r"\[\[[^\]]*\]\]\s*", "", stmt)
                stmt = re.sub(r"^[^A-Za-z_]*", "", stmt).strip()
                if not stmt:
                    continue
                for carrier, pat in carrier_pats:
                    if not pat.search(stmt):
                        continue
                    is_accessor = re.search(
                        rf"\b{re.escape(carrier)}\s*(?:->|\.)\s*[A-Za-z_]\w*"
                        rf"(?:Length|length|Size|size|Capacity|capacity)\w*\s*\(",
                        stmt,
                    )
                    assign = re.search(
                        rf"(?<![=!<>])\b{re.escape(carrier)}\s*=(?![=])", stmt
                    )
                    is_alloc_assign = bool(assign) and bool(
                        _CARRIER_EXTENT_RVALUE_RE.search(stmt[assign.end():])
                    )
                    if not (is_accessor or is_alloc_assign):
                        continue
                    if hop == 1 and is_alloc_assign:
                        for receiver in _CARRIER_RECEIVER_RE.findall(stmt[assign.end():]):
                            if receiver not in carriers and receiver not in _C_KEYWORDS:
                                next_carriers.append(receiver)
                    variants = {stmt, f"{stmt};", _strip_enclosing_parens(stmt)}
                    if variants & guard_texts or variants & code_texts:
                        continue
                    if stmt in seen:
                        continue
                    seen.add(stmt)
                    if is_alloc_assign:
                        kind = 0
                    elif re.search(r"(?<![=!<>])=(?![=])", stmt):
                        # Accessor feeding a named variable (`len = obj->DataLength()`).
                        kind = 1
                    else:
                        # Bare accessor inside a larger expression (log/trace noise).
                        kind = 2
                    candidates.append((func_name, stmt, kind, hop))
                    break
        active = _dedup_preserve_order(next_carriers)

    # Rank: provenance (clone/alloc assignments) first, then extent accessors
    # captured into variables, bare accessor expressions last; hop-1 carriers
    # before hop-2. Deterministic tie-break by function/text.
    candidates.sort(key=lambda item: (item[3], item[2], item[0], item[1]))
    return [
        f"`{func_name}`: `{stmt}`"
        for func_name, stmt, _kind, _hop in candidates[:CARRIER_EXTENT_MAX_PER_SINK]
    ]


_LIFETIME_FREE_CALL_RE = re.compile(
    r"\b(?P<callee>free|kfree|kfree_sensitive|kvfree|vfree|kzfree|"
    r"dma_free_coherent|dma_free_wc|pci_free_consistent)\s*\((?P<args>[^;{}]*)\)\s*;"
)


_LIFETIME_PUBLISH_CALLEE_RE = re.compile(
    r"(?i)(insert|store|register|set_drvdata|push|enqueue|list_add|hlist_add|"
    r"xa_store|hash_add|device_add|cdev_add|misc_register)"
)


_LIFETIME_REACQUIRE_CALLEE_RE = re.compile(r"(?i)(get|lookup|find|fetch)")


_LIFETIME_REMOVE_CALLEE_RE = re.compile(r"(?i)(remove|delete|unlink|erase|_del\b)")


_LIFETIME_FRAMEWORK_REGISTER_RE = re.compile(
    r"(?i)(device_add|cdev_add|misc_register|register_netdev|kobject_add)"
)


_LIFETIME_LOCK_RE = re.compile(
    r"\b(?:EnterCriticalSection|mutex_lock|spin_lock\w*|read_lock|write_lock|"
    r"rcu_read_lock)\s*\(\s*&?\s*([^;,)]*)"
)


_LIFETIME_UNLOCK_RE = re.compile(
    r"\b(?:LeaveCriticalSection|mutex_unlock|spin_unlock\w*|read_unlock|"
    r"write_unlock|rcu_read_unlock)\s*\(\s*&?\s*([^;,)]*)"
)


_LIFETIME_FREE_MULTI_ARG = {"dma_free_coherent", "dma_free_wc", "pci_free_consistent"}


def _lifetime_locks_covering(body: str, position: int) -> List[str]:
    """Lock objects whose matched lock...unlock region covers byte `position`.
    Best-effort, positional."""
    regions: List[Tuple[int, int, str]] = []
    for lock_match in _LIFETIME_LOCK_RE.finditer(body):
        lock_obj = re.sub(r"\s+", "", lock_match.group(1) or "")
        for unlock_match in _LIFETIME_UNLOCK_RE.finditer(body, lock_match.end()):
            unlock_obj = re.sub(r"\s+", "", unlock_match.group(1) or "")
            if unlock_obj == lock_obj:
                regions.append((lock_match.start(), unlock_match.end(), lock_obj))
                break
    return sorted({obj for start, end, obj in regions if start <= position <= end})


def _lifetime_lock_label(body: str, position: int) -> str:
    covering = _lifetime_locks_covering(body, position)
    return f"under {covering}" if covering else "none"


def _lifetime_freed_expression(callee: str, args_text: str) -> Optional[str]:
    args = _split_call_arguments(args_text)
    index = 2 if callee in _LIFETIME_FREE_MULTI_ARG else 0
    if len(args) <= index:
        return None
    expr = _normalize_space(args[index]).rstrip(";").strip()
    while expr.startswith("("):
        close = expr.find(")")
        if close < 0:
            break
        expr = expr[close + 1:].strip()
    expr = expr.lstrip("&*").strip()
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*", expr):
        return None
    return expr


def _lifetime_normalize_arg(arg: str) -> str:
    """Cast/whitespace-insensitive argument identity: `(void*)appWindow` and
    `appWindow` denote the same argument."""
    text = re.sub(r"\s+", "", arg)
    while text.startswith("("):
        close = text.find(")")
        if close < 0:
            break
        text = text[close + 1:]
    return text


_LIFETIME_CALL_KEYWORDS = {
    "if", "while", "for", "switch", "return", "sizeof", "defined",
}


def _lifetime_iter_calls(body: str) -> Iterable[Tuple[str, int, int, str]]:
    """Yield (callee, call_start, call_end, args_text) with balanced parens, so
    calls nested in `if (...)` conditions or casts are still found."""
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
        callee = match.group(1)
        if callee in _LIFETIME_CALL_KEYWORDS:
            continue
        depth = 0
        index = match.end() - 1  # at '('
        args_start = index + 1
        while index < len(body):
            char = body[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if index >= len(body):
            continue
        yield callee, match.start(), index, body[args_start:index]


def _lifetime_call_statement(body: str, start: int, end: int) -> str:
    line_start = body.rfind("\n", 0, start) + 1
    semi = body.find(";", end)
    if semi < 0:
        semi = body.find("\n", end)
    if semi < 0:
        semi = end + 1
    return _normalize_space(body[line_start:semi + 1])


def _lifetime_call_sites(
    bodies: Dict[str, str],
    arg_expr: str,
    callee_re: Any,
) -> List[Dict[str, Any]]:
    """Calls whose argument list contains `arg_expr` as an exact argument and
    whose callee matches `callee_re`."""
    sites: List[Dict[str, Any]] = []
    target = _lifetime_normalize_arg(arg_expr)
    for func_name, body in bodies.items():
        for callee, start, end, args_text in _lifetime_iter_calls(body):
            if not callee_re.search(callee):
                continue
            arguments = _split_call_arguments(args_text)
            normalized_args = [_lifetime_normalize_arg(arg) for arg in arguments]
            if target not in normalized_args:
                continue
            sites.append({
                "func": func_name,
                "statement": _lifetime_call_statement(body, start, end),
                "callee": callee,
                "container": _normalize_space(arguments[0]) if arguments else "",
                "position": start,
            })
    return sites


def _build_lifetime_links(engine: "StaticAnalysisEngine") -> List[Dict[str, Any]]:
    """File-wide free -> publish -> reacquire links, one per freed object.

    A link is kept only when it carries actionable cross-function evidence:
    a kept publish site (container with an in-file reacquire, a field store
    read elsewhere, or a framework registration), or an entry-point-callback
    same-type use pair. Anything else is the single-function status quo the
    existing lifecycle machinery already covers.
    """
    bodies: Dict[str, str] = {}
    for func_name in _safe_list(getattr(engine, "defined_function_names", [])):
        try:
            bodies[str(func_name)] = engine.get_code(str(func_name)) or ""
        except Exception:
            continue
    if not bodies:
        return []

    entry_points = set()
    try:
        entry_points = set(engine.externally_invoked_functions)
    except Exception:
        pass
    # A function installed as a `.release`-style callback IS the sanctioned
    # destruction point (e.g., ism_dev_release after the CVE-2025-21856 fix):
    # frees there are refcount-contract compliant, not a lifetime defect.
    release_handlers = set(re.findall(
        r"(?:\.|->)\s*release\s*=\s*([A-Za-z_]\w*)\s*;",
        "\n".join(bodies.values()),
    ))

    links: List[Dict[str, Any]] = []
    for func_name, body in bodies.items():
        if func_name in release_handlers:
            continue
        for free_match in _LIFETIME_FREE_CALL_RE.finditer(body):
            expr = _lifetime_freed_expression(
                free_match.group("callee"), free_match.group("args")
            )
            if not expr:
                continue
            base = re.split(r"\s*(?:->|\.)\s*", expr)[0]
            is_plain_var = base == expr
            free_site = {
                "func": func_name,
                "statement": _normalize_space(free_match.group(0)),
                "lock": _lifetime_lock_label(body, free_match.start()),
            }
            # Origins: every `expr = <rhs>;` before the free in this function.
            origins: List[Dict[str, str]] = []
            for assign in re.finditer(
                rf"(?<![=!<>\w]){re.escape(expr)}\s*=\s*([^;]+);",
                body[: free_match.start()],
                flags=re.S,
            ):
                rhs = _normalize_space(assign.group(1))
                if re.fullmatch(r"(?:NULL|nullptr|0)", rhs):
                    continue
                call = re.search(r"\b([A-Za-z_]\w*)\s*\(", rhs)
                origins.append({
                    "statement": f"{expr} = {rhs};",
                    "producer": call.group(1) if call else "",
                })
            param_cast = re.fullmatch(
                r"\(\s*([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)\s*\*+\s*\)\s*"
                r"([A-Za-z_]\w*)",
                origins[-1]["statement"].split("=", 1)[1].strip().rstrip(";"),
            ) if origins else None

            # Publish sites: direct (expr as exact call arg), plus
            # producer-mediated (the producer publishes its return value).
            publishes: List[Dict[str, str]] = []
            for site in _lifetime_call_sites(
                bodies, expr, _LIFETIME_PUBLISH_CALLEE_RE
            ):
                site = dict(site)
                site["via"] = ""
                publishes.append(site)
            if is_plain_var:
                # `device_add(&ism->dev)`-style: &base->member as the argument.
                member_prefixes = (f"&{base}->", f"&{base}.")
                for fname, fbody in bodies.items():
                    for callee, start, end, args_text in _lifetime_iter_calls(fbody):
                        if not _LIFETIME_PUBLISH_CALLEE_RE.search(callee):
                            continue
                        arguments = _split_call_arguments(args_text)
                        if not any(
                            _lifetime_normalize_arg(arg).startswith(member_prefixes)
                            for arg in arguments
                        ):
                            continue
                        publishes.append({
                            "func": fname,
                            "statement": _lifetime_call_statement(fbody, start, end),
                            "callee": callee,
                            "container": _normalize_space(arguments[0]) if arguments else "",
                            "position": start,
                            "via": "",
                        })
            # Producer-mediated: expr = g(...); inside g, g's returned variable
            # (or expr itself) is published.
            producers = [
                origin["producer"] for origin in origins
                if origin["producer"] and origin["producer"] in bodies
            ]
            for producer in producers:
                producer_body = bodies[producer]
                return_vars = set(re.findall(
                    r"\breturn\s+([A-Za-z_]\w*)\s*;", producer_body
                ))
                if is_plain_var:
                    return_vars.add(base)
                for ret_var in return_vars:
                    for site in _lifetime_call_sites(
                        {producer: producer_body}, ret_var,
                        _LIFETIME_PUBLISH_CALLEE_RE,
                    ):
                        site = dict(site)
                        site["via"] = f"producer {producer}"
                        publishes.append(site)

            # Keep a publish only with evidence the object is reachable later:
            # a reacquire of the same container, or a framework registration.
            deduped_publishes: List[Dict[str, str]] = []
            seen_publish: Set[Tuple[str, str]] = set()
            for site in publishes:
                marker = (site["func"], re.sub(r"\s+", "", site["statement"]))
                if marker in seen_publish:
                    continue
                seen_publish.add(marker)
                deduped_publishes.append(site)
            kept: List[Dict[str, Any]] = []
            for site in deduped_publishes:
                container = site["container"]
                reacquires = [
                    r for r in _lifetime_call_sites(
                        bodies, container, _LIFETIME_REACQUIRE_CALLEE_RE
                    )
                    if not (r["func"] == site["func"] and r["statement"] == site["statement"])
                ] if container else []
                removals = [
                    r for r in _lifetime_call_sites(
                        bodies, container, _LIFETIME_REMOVE_CALLEE_RE
                    )
                ] if container else []
                framework = bool(
                    _LIFETIME_FRAMEWORK_REGISTER_RE.search(site["callee"])
                )
                if not (reacquires or framework):
                    continue
                kept.append({
                    **site,
                    "reacquires": reacquires[:LIFETIME_LINKS_MAX_SITES],
                    "removals": removals[:LIFETIME_LINKS_MAX_SITES],
                    "framework": framework,
                    "lock": _lifetime_lock_label(
                        bodies.get(site["func"], ""), site["position"]
                    ),
                })
            publishes = kept

            # Fallback: entry-point parameter cast freed here, same-typed object
            # dereferenced in OTHER entry points (cross-callback lifetime pair).
            same_type_uses: List[Dict[str, str]] = []
            if not publishes and is_plain_var and param_cast and func_name in entry_points:
                var_type = param_cast.group(1)
                for other_func, other_body in bodies.items():
                    if other_func == func_name or other_func not in entry_points:
                        continue
                    decl = re.search(
                        rf"\b{re.escape(var_type)}\s*\*+\s*([A-Za-z_]\w*)",
                        other_body,
                    )
                    if not decl:
                        continue
                    other_var = decl.group(1)
                    derefs = list(re.finditer(
                        rf"^[^;\n]*\b{re.escape(other_var)}\s*->[^;]*;",
                        other_body, flags=re.M,
                    ))
                    if not derefs:
                        continue
                    real_derefs = [
                        m for m in derefs
                        if not re.match(
                            r"\s*(?:WINPR_ASSERT|ASSERT|assert|BUG_ON)\b",
                            m.group(0),
                        )
                    ]
                    deref = real_derefs[0] if real_derefs else derefs[0]
                    acquires = [
                        m for m in re.finditer(
                            rf"^[^;\n]*\b{re.escape(other_var)}\s*=[^;]*;",
                            other_body, flags=re.M,
                        )
                        if m.start() < deref.start()
                        and not re.fullmatch(
                            r"\s*(?:NULL|nullptr|0)\s*;",
                            m.group(0).split("=", 1)[-1].strip(),
                        )
                    ]
                    acquire = acquires[-1] if acquires else None
                    statements = [
                        _normalize_space(m.group(0))
                        for m in (acquire, deref) if m
                    ]
                    same_type_uses.append({
                        "func": other_func,
                        "type": var_type,
                        "statements": statements[:2],
                        "lock": _lifetime_lock_label(other_body, deref.start()),
                    })
                    if len(same_type_uses) >= LIFETIME_LINKS_MAX_SITES:
                        break

            if not publishes and not same_type_uses:
                continue

            involved = {func_name} | {p for p in producers}
            involved |= {site["func"] for site in publishes}
            for site in publishes:
                involved |= {r["func"] for r in site["reacquires"]}
            involved |= {use["func"] for use in same_type_uses}
            # Reacquire getter callers: where the dangling object would be used.
            getter_callers: Dict[str, List[str]] = {}
            for site in publishes:
                for reacquire in site["reacquires"]:
                    getter = reacquire["func"]
                    call_re = re.compile(rf"\b{re.escape(getter)}\s*\(")
                    getter_callers[getter] = [
                        fname for fname, fbody in bodies.items()
                        if fname != getter and call_re.search(fbody)
                    ][:LIFETIME_LINKS_MAX_SITES]
                    involved |= set(getter_callers[getter])
            framework_release_assigned = None
            if any(site["framework"] for site in publishes):
                framework_release_assigned = bool(re.search(
                    r"(?:\.|->)\s*release\s*=", "\n".join(bodies.values())
                ))

            links.append({
                "expr": expr,
                "base": base,
                "free_site": free_site,
                "origins": origins[:2],
                "publishes": publishes[:LIFETIME_LINKS_MAX_SITES],
                "same_type_uses": same_type_uses,
                "getter_callers": getter_callers,
                "framework_release_assigned": framework_release_assigned,
                "involved_functions": sorted(involved),
            })

    # Rank: publish+reacquire links first, then framework, then same-type;
    # cap per file to bound prompt noise.
    def rank(link: Dict[str, Any]) -> Tuple[int, str]:
        if any(s["reacquires"] for s in link["publishes"]):
            tier = 0
        elif any(s["framework"] for s in link["publishes"]):
            tier = 1
        else:
            tier = 2
        return tier, link["expr"]

    links.sort(key=rank)
    return links[:LIFETIME_LINKS_MAX_PER_FILE]


def _format_lifetime_links(links: Sequence[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for index, link in enumerate(links, 1):
        free_site = link["free_site"]
        lines.append(
            f"[L{index}] `{free_site['statement']}` in `{free_site['func']}` "
            f"[lock covering free: {free_site['lock']}]"
        )
        for origin in link["origins"]:
            lines.append(f"    origin: `{origin['statement']}` (same function)")
        for site in link["publishes"]:
            via = f" (via {site['via']})" if site.get("via") else ""
            lines.append(
                f"    publish: `{site['statement']}` in `{site['func']}`{via} "
                f"[lock: {site['lock']}]"
            )
            for reacquire in site["reacquires"]:
                callers = link["getter_callers"].get(reacquire["func"]) or []
                caller_note = (
                    f"; in-file callers of `{reacquire['func']}`: {', '.join(callers)}"
                    if callers else ""
                )
                lines.append(
                    f"    reacquire of `{site['container']}`: "
                    f"`{reacquire['statement']}` in `{reacquire['func']}`{caller_note}"
                )
            removals = site["removals"]
            lines.append(
                f"    unregister of `{site['container']}`: "
                + (
                    "; ".join(
                        f"`{item['statement']}` in `{item['func']}`"
                        for item in removals
                    )
                    if removals else "none found in file"
                )
            )
            if site["framework"]:
                lines.append(
                    "    framework registration: `.release`-style release-callback "
                    f"assignment in file: "
                    f"{'FOUND' if link['framework_release_assigned'] else 'NONE'}"
                )
        for use in link["same_type_uses"]:
            statements = " | ".join(f"`{stmt}`" for stmt in use["statements"])
            lines.append(
                f"    same-type ({use['type']}*) object dereferenced in entry point "
                f"`{use['func']}`: {statements} [lock: {use['lock']}]"
            )
        if link["publishes"]:
            lines.append(
                "    note: if no unregister/removal dominates this free, a later "
                "reacquire (or a framework-held reference) returns the released "
                "object (free-without-unregister UAF candidate)."
            )
        elif link["same_type_uses"]:
            lines.append(
                "    note: the freed object and the same-typed objects above may "
                "alias one registered callback allocation; the free in one entry "
                "point can precede or race a use in another (cross-entry-point "
                "UAF candidate) - lock annotations show whether the sites are "
                "serialized."
            )
    return "\n".join(lines)


def _attach_lifetime_links(
    tasks: Sequence[MultiSourcePathTask],
    engine: "StaticAnalysisEngine",
) -> None:
    """Attach rendered lifetime-link evidence to the tasks that touch the
    involved functions. Shadow field only: never in signatures/grouping.
    Any failure leaves tasks unchanged."""
    if not LIFETIME_LINKS:
        return
    try:
        links = _build_lifetime_links(engine)
    except Exception as exc:
        print(f"  - Lifetime-link scan warning: {exc}")
        return
    if not links:
        return
    attached = 0
    for task in tasks:
        try:
            text_parts = [task.target_function]
            for subpath in task.source_subpaths:
                for sink in subpath.sinks:
                    text_parts.append(str(sink.get("operation") or ""))
                for fact in subpath.facts:
                    text_parts.append(str(fact.get("code") or ""))
            task_text = "\n".join(text_parts)
            relevant = [
                link for link in links
                if any(
                    re.search(rf"\b{re.escape(fname)}\b", task_text)
                    for fname in link["involved_functions"]
                )
            ]
            if not relevant:
                continue
            task.lifetime_link_context = _format_lifetime_links(
                relevant[:LIFETIME_LINKS_MAX_PER_TASK]
            )
            attached += 1
        except Exception:
            continue
    print(
        f"  - Lifetime-link evidence: {len(links)} link(s) built, attached to "
        f"{attached} task(s)."
    )


def _sink_path_functions(
    task: MultiSourcePathTask,
    sink: Dict[str, Any],
) -> Tuple[str, List[str]]:
    """(sink function, [sink function] + task path functions), deduped."""
    sink_func = str(sink.get("function") or task.target_function)
    return sink_func, _dedup_preserve_order(
        [sink_func]
        + [name for name in _task_path_functions(task) if name != sink_func]
    )


def _entity_conditions_for_sink(
    task: MultiSourcePathTask,
    subpath: SourceSubpath,
    sink: Dict[str, Any],
    scan_of: Any,
    engine: "StaticAnalysisEngine",
    guard_texts: Set[str],
    code_texts: Set[str],
) -> List[str]:
    """Record if/while conditions referencing sink-chain entities, drawn only
    from the functions the task already includes (sink function + path
    functions). Sink-function conditions rank first, then by number of
    referenced entities. Conditions already present in the prompt text pools
    are skipped. Rendering-only shadow data; never used for filtering."""
    entities = _sink_entity_set(subpath, sink)
    if not entities:
        return []
    patterns = [(name, re.compile(r"\b" + re.escape(name) + r"\b"))
                for name in entities]
    sink_func, functions = _sink_path_functions(task, sink)
    # The decisive guard may sit in a direct caller of the sink function rather
    # than on an extracted path (e.g. the caller validates before delegating).
    if ENTITY_CONDITIONS_CALLERS:
        try:
            callers = _safe_list(engine.caller_index.get(sink_func))
        except Exception:
            callers = []
        for caller in callers:
            caller = str(caller)
            if caller and caller not in functions:
                functions.append(caller)
    # NULL checks on a struct field often live in sibling functions, not in
    # callers (`if (!transport || ...)` in sendmsg while the sink dereferences
    # vsk->transport in has_data). Field names are specific enough to scan the
    # whole file; plain variables stay path-scoped.
    field_entities = _sink_field_entities(sink)
    field_patterns = [(name, re.compile(r"\b" + re.escape(name) + r"\b"))
                      for name in field_entities]
    in_scope = set(functions)
    filewide_functions: List[str] = []
    if ENTITY_CONDITIONS_FIELD_FILEWIDE and field_patterns:
        for name in _safe_list(getattr(engine, "defined_function_names", [])):
            name = str(name)
            if name and name not in in_scope:
                filewide_functions.append(name)
    candidates: List[Tuple[str, str, int]] = []
    for func_name in functions + filewide_functions:
        active_entities, active_patterns = entities, patterns
        if func_name not in in_scope:
            # Off-path non-caller function: only field-entity matches count.
            active_entities, active_patterns = field_entities, field_patterns
        scan = scan_of(func_name)
        cond_texts = [
            normalized
            for normalized in (
                _normalize_space(str(cond.get("raw") or ""))
                for cond in _safe_list(scan.get("conditions"))
            )
            if normalized
        ]
        if not cond_texts:
            # Scan yielded nothing usable (e.g. unparseable snippet): fall back
            # to the pure-text indexer over the raw function body.
            try:
                code = engine.get_code(func_name) or ""
            except Exception:
                code = ""
            cond_texts = _extract_text_entity_conditions(code, active_entities)
        for text in cond_texts:
            bare = _strip_enclosing_parens(text)
            if (text in guard_texts or text in code_texts
                    or bare in guard_texts or bare in code_texts):
                continue
            matched = sum(1 for _, pat in active_patterns if pat.search(text))
            if matched:
                candidates.append((func_name, text, matched))
    candidates.sort(key=lambda item: (item[0] != sink_func, -item[2], item[0], item[1]))
    output: List[str] = []
    seen: Set[str] = set()
    for func_name, text, _matched in candidates:
        if text in seen:
            continue
        seen.add(text)
        output.append(f"`{func_name}`: `{text}`")
        if len(output) >= ENTITY_CONDITIONS_MAX_PER_SINK:
            break
    return output


_ENTITY_ALLOC_ASSIGN = re.compile(r"(?<![=!<>])=(?![=])")


_ENTITY_ALLOC_CALLEE = re.compile(r"alloc", re.I)


_ENTITY_SIZEOF = re.compile(r"\bsizeof\b")


def _extract_text_entity_allocations(
    code: str,
    entities: Sequence[str],
    cap: int = 20,
) -> List[str]:
    """Pure-text indexer: assignment statements whose rvalue carries
    allocation/size semantics (alloc-family callee or sizeof) and that mention
    any entity (word-boundary). Statements are joined across lines up to the
    terminating `;`, at most 3 lines. Deterministic and bounded by `cap`."""
    if not entities or not code:
        return []
    pats = [re.compile(r"\b" + re.escape(e) + r"\b") for e in entities if e]
    if not pats:
        return []
    results: List[str] = []
    lines = code.splitlines()
    for index, line in enumerate(lines):
        if len(results) >= cap:
            break
        if not _ENTITY_ALLOC_ASSIGN.search(line):
            continue
        stmt_parts = [line.strip()]
        if ";" not in line:
            for follow in lines[index + 1:index + 3]:
                stmt_parts.append(follow.strip())
                if ";" in follow:
                    break
        stmt = _normalize_space(" ".join(stmt_parts)).rstrip(";").strip()
        assign = _ENTITY_ALLOC_ASSIGN.search(stmt)
        if not assign:
            continue
        rvalue = stmt[assign.end():]
        if not (_ENTITY_ALLOC_CALLEE.search(rvalue) or _ENTITY_SIZEOF.search(rvalue)):
            continue
        if any(pat.search(stmt) for pat in pats):
            results.append(stmt)
    return results


def _entity_allocations_for_sink(
    task: MultiSourcePathTask,
    subpath: SourceSubpath,
    sink: Dict[str, Any],
    engine: "StaticAnalysisEngine",
    guard_texts: Set[str],
    code_texts: Set[str],
) -> List[str]:
    """Record allocation/capacity statements referencing the same entity set
    as `_entity_conditions_for_sink`, over the same function scope and with
    the same ranking/dedup rules. Rendering-only shadow data; never used for
    filtering."""
    entities = _sink_entity_set(subpath, sink)
    if not entities:
        return []
    patterns = [(name, re.compile(r"\b" + re.escape(name) + r"\b"))
                for name in entities]
    sink_func, functions = _sink_path_functions(task, sink)
    # Field capacity is often established in an init function that is on no
    # evidence path (`obj->field = kzalloc(N * sizeof(...))`). Field names are
    # specific enough to scan the whole file; plain variables stay path-scoped.
    field_patterns = [
        (name, re.compile(r"\b" + re.escape(name) + r"\b"))
        for name in _sink_field_entities(sink)
    ]
    path_function_set = set(functions)
    if ENTITY_ALLOCATIONS_FILEWIDE and field_patterns:
        for name in _safe_list(getattr(engine, "defined_function_names", [])):
            name = str(name)
            if name and name not in path_function_set:
                functions.append(name)
    candidates: List[Tuple[str, str, int]] = []
    for func_name in functions:
        try:
            code = engine.get_code(func_name) or ""
        except Exception:
            code = ""
        active_entities, active_patterns = entities, patterns
        if func_name not in path_function_set:
            # Off-path function: only field-entity matches are specific enough.
            active_entities = _sink_field_entities(sink)
            active_patterns = field_patterns
        for text in _extract_text_entity_allocations(code, active_entities):
            variants = {text, f"{text};", _strip_enclosing_parens(text)}
            if variants & guard_texts or variants & code_texts:
                continue
            matched = sum(1 for _, pat in active_patterns if pat.search(text))
            if matched:
                candidates.append((func_name, text, matched))
    candidates.sort(key=lambda item: (item[0] != sink_func, -item[2], item[0], item[1]))
    output: List[str] = []
    seen: Set[str] = set()
    for func_name, text, _matched in candidates:
        if text in seen:
            continue
        seen.add(text)
        output.append(f"`{func_name}`: `{text}`")
        if len(output) >= ENTITY_ALLOCATIONS_MAX_PER_SINK:
            break
    return output


def _attach_vec_counterevidence(
    tasks: Sequence[MultiSourcePathTask],
    engine: "StaticAnalysisEngine",
) -> None:
    """Attach hypothesis-relevant retrieval evidence (VEC, stored grouped by
    applicable family) to each sink; rendered only into the verification
    prompt, never into any signature/grouping/filtering logic. Keeps only
    information not yet present in the prompt. Any single-point failure skips
    that sink and never affects task construction."""
    if not VEC_COUNTER_EVIDENCE:
        return
    scan_cache: Dict[str, Dict[str, Any]] = {}

    def scan_of(func_name: str) -> Dict[str, Any]:
        if func_name not in scan_cache:
            try:
                code = engine.get_code(func_name) or ""
            except Exception:
                code = ""
            try:
                scan_cache[func_name] = _vec_scan_function(code)
            except Exception:
                scan_cache[func_name] = {"conditions": [], "writes": [],
                                         "capacities": [], "helpers": [], "clamps": []}
        return scan_cache[func_name]

    attached = 0
    signal_attached = 0
    entity_attached = 0
    alloc_attached = 0
    all_scans: Optional[Dict[str, Dict[str, Any]]] = None

    def file_scans() -> Dict[str, Dict[str, Any]]:
        # Lazily build the whole-file scan (only when a null-family sink with a
        # producer call exists)
        nonlocal all_scans
        if all_scans is None:
            all_scans = {}
            for func_name in _safe_list(getattr(engine, "defined_function_names", [])):
                try:
                    all_scans[str(func_name)] = scan_of(str(func_name))
                except Exception:
                    continue
        return all_scans

    for task in tasks:
        guard_texts: Set[str] = set()
        code_texts: Set[str] = set()
        for subpath in task.source_subpaths:
            for fact in _prompt_facts_for_subpath(subpath):
                for guard in _safe_list(fact.get("controls")):
                    guard_texts.add(_normalize_space(str(guard)))
                code = _normalize_space(str(fact.get("code") or ""))
                if code:
                    code_texts.add(code)
            for sink in subpath.sinks:
                for guard in _safe_list(sink.get("controls")):
                    guard_texts.add(_normalize_space(str(guard)))
                operation = _normalize_space(str(sink.get("operation") or ""))
                if operation:
                    code_texts.add(operation)
        for subpath in task.source_subpaths:
            for sink in subpath.sinks:
                if ENTITY_CONDITIONS:
                    try:
                        entries = _entity_conditions_for_sink(
                            task, subpath, sink, scan_of, engine,
                            guard_texts, code_texts,
                        )
                        if entries:
                            sink["vec_entity_conditions"] = entries
                            entity_attached += 1
                    except Exception:
                        pass
                    if ENTITY_ALLOCATIONS:
                        try:
                            alloc_entries = _entity_allocations_for_sink(
                                task, subpath, sink, engine,
                                guard_texts, code_texts,
                            )
                            if alloc_entries:
                                sink["vec_entity_allocations"] = alloc_entries
                                alloc_attached += 1
                        except Exception:
                            pass
                if CARRIER_EXTENT:
                    try:
                        carrier_entries = _carrier_extent_for_sink(
                            task, sink, engine, guard_texts, code_texts,
                        )
                        if carrier_entries:
                            sink["vec_carrier_extent"] = carrier_entries
                    except Exception:
                        pass
                try:
                    families = _vec_applicable_families(sink)
                except Exception:
                    continue
                families = [f for f in families if f in VEC_FAMILIES]
                if not families:
                    continue
                sink_func = str(sink.get("function") or task.target_function)
                scan = scan_of(sink_func)
                evidence: Dict[str, Dict[str, List[str]]] = {}
                for family in families:
                    try:
                        retrieval = _vec_retrieve(sink, family, scan)
                        new_only = _vec_select_new(retrieval, guard_texts, code_texts)
                        groups = _vec_render_grouped(new_only, VEC_MAX_ITEMS)
                    except Exception:
                        groups = {}
                    if groups:
                        evidence[family] = groups
                if evidence:
                    sink["vec_evidence"] = evidence
                    attached += 1
                if "null" not in families or not VEC_NULLABILITY_SIGNALS:
                    continue
                try:
                    producers = _vec_sink_producer_calls(sink)
                except Exception:
                    producers = []
                if not producers:
                    continue
                signals: List[str] = []
                for producer in producers:
                    try:
                        sites = _vec_find_producer_null_checks(
                            file_scans(), producer["callee"], sink_func,
                            max_sites=VEC_NULLABILITY_MAX_SITES,
                        )
                    except Exception:
                        sites = []
                    for site in sites:
                        # Skip NULL tests already present in the prompt text pool
                        if site["raw"] in guard_texts:
                            continue
                        signals.append(
                            f"producer `{producer['call_text']}` is NULL-tested "
                            f"elsewhere in this file (`{site['func']}`: "
                            f"`{site['raw']}`): the codebase treats this producer "
                            f"as returning a nullable result - this is SUPPORTING "
                            f"evidence of a concrete nullable origin, NOT a "
                            f"blocker; verify it is consistent with the current "
                            f"path before relying on it"
                        )
                if signals:
                    sink["vec_nullability_signals"] = _dedup_preserve_order(
                        signals)[:VEC_NULLABILITY_MAX_SITES * 2]
                    signal_attached += 1
    if attached:
        print(f"  - VEC retrieved evidence attached to {attached} sink(s) "
              f"(families: {sorted(VEC_FAMILIES)}).")
    if signal_attached:
        print(f"  - VEC nullability signals attached to {signal_attached} sink(s).")
    if entity_attached:
        print(f"  - VEC entity conditions attached to {entity_attached} sink(s).")
    if alloc_attached:
        print(f"  - VEC entity allocations attached to {alloc_attached} sink(s).")


_VEC_CWE_FAMILY_PATTERNS = (
    ("null", re.compile(r"CWE-476|NULL", re.I)),
    ("integer", re.compile(r"CWE-19[01]|INTEGER|OVERFLOW|UNDERFLOW", re.I)),
    ("bounds", re.compile(
        r"CWE-(119|12[0-7]|78[78])|BUFFER|BOUNDS?|OUT-OF-BOUNDS|OOB", re.I)),
    ("lifetime", re.compile(r"CWE-41[56]|USE-AFTER-FREE|DOUBLE.?FREE", re.I)),
)


def _vec_families_for_hypothesis(hypothesis: Dict[str, Any]) -> List[str]:
    """Select retrieval-evidence families from the hypothesis mechanism
    (hypothesis-conditioned evidence selection).

    The hypothesis-tagged mechanism family may differ from the sink's static
    primary classification (e.g. memcpy is statically classed as bounds while
    the hypothesis says integer overflow); families are chosen here from the
    hypothesis CWE/type text, falling back to all enabled families when
    unrecognized."""
    text = (
        f"{hypothesis.get('cwe_id') or ''} "
        f"{hypothesis.get('potential_vulnerability_type') or ''}"
    )
    families = [family for family, pattern in _VEC_CWE_FAMILY_PATTERNS
                if pattern.search(text)]
    enabled = [family for family in families if family in VEC_FAMILIES]
    return enabled or sorted(VEC_FAMILIES)


def _format_vec_counterevidence(
    task: MultiSourcePathTask,
    hypotheses: Sequence[Dict[str, Any]],
) -> str:
    """Aggregate the retrieval-evidence section by hypothesis mechanism family
    plus referenced Sink IDs (grouped rendering)."""
    sink_by_id: Dict[str, Dict[str, Any]] = {}
    for subpath in task.source_subpaths:
        for sink in subpath.sinks:
            sink_by_id[str(sink.get("sink_id"))] = sink
    lines: List[str] = []
    for hypothesis in hypotheses:
        families = set(_vec_families_for_hypothesis(hypothesis))
        defensive: List[str] = []
        updates: List[str] = []
        signals: List[str] = []
        entity_conditions: List[str] = []
        entity_allocations: List[str] = []
        carrier_extent: List[str] = []
        for sink_id in _safe_list(hypothesis.get("relevant_sink_ids")):
            sink = sink_by_id.get(str(sink_id))
            if not sink:
                continue
            evidence = sink.get("vec_evidence") or {}
            for family, groups in evidence.items():
                if family not in families:
                    continue
                defensive.extend(_safe_list(groups.get("candidate_defensive")))
                updates.extend(_safe_list(groups.get("unresolved_state_updates")))
            signals.extend(_safe_list(sink.get("vec_nullability_signals")))
            if ENTITY_CONDITIONS:
                entity_conditions.extend(
                    _safe_list(sink.get("vec_entity_conditions"))
                )
                if ENTITY_ALLOCATIONS:
                    entity_allocations.extend(
                        _safe_list(sink.get("vec_entity_allocations"))
                    )
            if CARRIER_EXTENT:
                carrier_extent.extend(
                    _safe_list(sink.get("vec_carrier_extent"))
                )
        defensive = _dedup_preserve_order(defensive)
        updates = _dedup_preserve_order(updates)
        signals = _dedup_preserve_order(signals)
        entity_conditions = _dedup_preserve_order(
            entity_conditions)[:ENTITY_CONDITIONS_MAX_RENDER]
        entity_allocations = _dedup_preserve_order(
            entity_allocations)[:ENTITY_ALLOCATIONS_MAX_RENDER]
        # Conditions first, then allocations, deduplicated across both.
        entity_items = _dedup_preserve_order(entity_conditions + entity_allocations)
        carrier_extent = _dedup_preserve_order(carrier_extent)[:CARRIER_EXTENT_MAX_RENDER]
        if not defensive and not updates and not signals and not entity_items and not carrier_extent:
            continue
        lines.append(f"{hypothesis.get('hypothesis_id', 'H?')}:")
        if defensive:
            lines.append(
                "  Candidate defensive evidence (verify dominance, path "
                "compatibility, and entity alignment yourself before treating "
                "any item as a blocker):"
            )
            lines.extend(f"  - {item}" for item in defensive)
        if updates:
            lines.append(
                "  Unresolved state updates (may support or refute; establish "
                "their effect on the hypothesized invariant):"
            )
            lines.extend(f"  - {item}" for item in updates)
        if signals:
            lines.append("  Nullable-origin signals (supporting, NOT blockers):")
            lines.extend(f"  - {signal}" for signal in signals)
        if entity_items:
            lines.append(
                "  Recorded conditions and allocation/capacity statements "
                "referencing cited entities (unjudged; verify dominance, path "
                "compatibility, and whether each constrains the hypothesized "
                "property):"
            )
            lines.extend(f"  - {item}" for item in entity_items)
        if carrier_extent:
            lines.append(
                "  Carrier extent statements (file-wide retrieval for objects "
                "whose methods produced the sink pointers/lengths; establish "
                "the carrier's extent from these before recording an "
                "unknown_capacity_or_extent gap):"
            )
            lines.extend(f"  - {item}" for item in carrier_extent)
    if not lines:
        # Empty string: the caller omits the retrieved-evidence section entirely.
        return ""
    return "\n".join(lines)


def _task_guard_annotations(task: MultiSourcePathTask) -> Dict[str, str]:
    """Map guard text to structured annotations. When the same text maps to
    multiple conflicting facts (different locations, different normalization
    results), it is left unannotated and rendered as raw text (conservative)."""
    if not GUARDFACT_PROMPT:
        return {}
    pool: Dict[str, Optional[Tuple[Any, Dict[str, Any]]]] = {}
    containers: List[Dict[str, Any]] = []
    for subpath in task.source_subpaths:
        containers.extend(subpath.sinks)
        containers.extend(_prompt_facts_for_subpath(subpath))
    for item in containers:
        for guard_fact in _safe_list(item.get("guard_facts")):
            if not isinstance(guard_fact, dict):
                continue
            raw = _normalize_space(str(guard_fact.get("raw") or ""))
            if not raw:
                continue
            identity = (
                json.dumps(guard_fact.get("normalized"), sort_keys=True, ensure_ascii=False),
                str(guard_fact.get("kind") or ""),
                str(guard_fact.get("polarity") or ""),
            )
            if raw not in pool:
                pool[raw] = (identity, guard_fact)
            elif pool[raw] is not None and pool[raw][0] != identity:
                pool[raw] = None
    return {
        raw: _guard_fact_annotation(entry[1])
        for raw, entry in pool.items()
        if entry and _guard_fact_annotation(entry[1])
    }



"""Generic text/JSON/normalization helpers and output-schema examples."""

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


from .structures import (
    MultiSourcePathTask,
    SourceSubpath,
)

from .config import (
    TRACE_ADAPTIVE,
    TRACE_CALLEE_DEPTH,
    TRACE_CALLEE_DEPTH_MAX,
)
from .schemas import (
    ScreeningResult,
    VerificationResult,
    _SCREENING_NATIVE,
    _VERIFICATION_NATIVE,
)


def _model_validate(model_cls: Any, payload: Any) -> Any:
    if hasattr(model_cls, "model_validate"):
        return model_cls.model_validate(payload)
    return model_cls.parse_obj(payload)


def _model_dump(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _message_to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    content = getattr(value, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if parts:
            return "\n".join(parts)
    if isinstance(value, BaseModel):
        return json.dumps(_model_dump(value), ensure_ascii=False)
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value or "")


def _invoke_text_model(llm: Any, prompt: str) -> str:
    return _message_to_text(llm.invoke(prompt))


def _coerce_structured_result(model_cls: Any, value: Any) -> Any:
    if isinstance(value, model_cls):
        return value
    # include_raw=True wrappers or provider-specific envelopes.
    if isinstance(value, dict) and "parsed" in value and value.get("parsed") is not None:
        return _coerce_structured_result(model_cls, value["parsed"])
    if isinstance(value, BaseModel):
        return _model_validate(model_cls, _model_dump(value))
    if isinstance(value, dict):
        return _model_validate(model_cls, value)
    text = _message_to_text(value)
    if hasattr(model_cls, "model_validate_json"):
        return model_cls.model_validate_json(text)
    return model_cls.parse_raw(text)


def _schema_instructions(model_cls: Any, parser: Any) -> str:
    if parser is not None:
        try:
            return parser.get_format_instructions()
        except Exception:
            pass
    if hasattr(model_cls, "model_json_schema"):
        schema = model_cls.model_json_schema()
    else:
        schema = model_cls.schema()
    return (
        "Return JSON only and conform exactly to this JSON Schema. "
        "Do not copy placeholder examples or add commentary:\n"
        + json.dumps(schema, ensure_ascii=False, indent=2)
    )


def _normalize_space(text: Optional[str]) -> str:
    return " ".join((text or "").split())


def _normalize_code(text: Optional[str]) -> str:
    text = _normalize_space(text)
    return text.rstrip(";")


def _safe_int(value: Any, default: int = -1) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _stable_hash(value: Any, length: int = 16) -> str:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:length]


def _safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


_PROOF_GAP_TYPES = {
    "missing_function_body",
    "unresolved_call_target",
    "missing_macro_definition",
    "unknown_source_origin",
    "unknown_capacity_or_extent",
    "unknown_alias_or_object_identity",
    "unknown_branch_compatibility",
    "missing_control_context",
    "external_runtime_semantics",
    "other",
}


def _normalize_string_list(value: Any) -> List[str]:
    return _dedup_preserve_order(
        normalized
        for item in _safe_list(value)
        if (normalized := _normalize_space(str(item or "")))
    )


def _normalize_evidence_requests(value: Any) -> List[Dict[str, str]]:
    requests: List[Dict[str, str]] = []
    for raw in _safe_list(value):
        if isinstance(raw, BaseModel):
            raw = _model_dump(raw)
        if isinstance(raw, str):
            raw = {"gap_type": "other", "symbol": "", "reason": raw}
        if not isinstance(raw, dict):
            continue
        gap_type = _normalize_space(str(raw.get("gap_type") or "other")).lower()
        if gap_type not in _PROOF_GAP_TYPES:
            gap_type = "other"
        symbol = _normalize_space(str(raw.get("symbol") or ""))
        reason = _normalize_space(str(raw.get("reason") or ""))
        requests.append({"gap_type": gap_type, "symbol": symbol, "reason": reason})
    return _dedup_preserve_order(requests)


def _normalize_boundary_status(value: Any) -> str:
    normalized = _normalize_space(str(value or "")).lower()
    if normalized == "established":
        return "Established"
    if normalized == "plausible":
        return "Plausible"
    return "Unknown"


def _normalize_confidence(value: Any) -> str:
    normalized = _normalize_space(str(value or "")).lower()
    if normalized == "high":
        return "High"
    if normalized == "low":
        return "Low"
    return "Medium"


def _normalize_finding_evidence_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    item["security_boundary"] = _normalize_space(
        str(item.get("security_boundary") or item.get("trust_boundary") or "Unknown")
    ) or "Unknown"
    item["boundary_status"] = _normalize_boundary_status(
        item.get("boundary_status", item.get("security_boundary_status"))
    )
    item["counterevidence"] = _normalize_string_list(
        item.get("counterevidence", item.get("counter_evidence"))
    )
    item["defenses_considered"] = _normalize_string_list(
        item.get("defenses_considered")
    )
    item["proof_gaps"] = _normalize_string_list(
        item.get("proof_gaps", item.get("evidence_gaps"))
    )
    item["evidence_requests"] = _normalize_evidence_requests(
        item.get("evidence_requests", item.get("requested_evidence"))
    )
    item["confidence"] = _normalize_confidence(item.get("confidence"))
    return item


def _call_edge_identity(
    caller: str,
    callee: str,
    start_byte: Any,
    operation: Any,
    controls: Any = None,
) -> str:
    """Identify a concrete callsite without turning guard variants into edges."""

    normalized_start = _safe_int(start_byte, -1)
    payload: Dict[str, Any] = {
        "caller": caller,
        "callee": callee,
        "callsite_start_byte": normalized_start,
        "operation": _normalize_code(operation),
    }
    # Text-only fallback sites can be ambiguous, so retain controls there. At a
    # concrete location, controls remain path facts/variants rather than edge IDs.
    if normalized_start < 0:
        payload["controls"] = sorted(_safe_list(controls))
    return _stable_hash(payload, 24)


def _dedup_preserve_order(items: Iterable[Any]) -> List[Any]:
    output: List[Any] = []
    seen: Set[str] = set()
    for item in items:
        marker = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(item)
    return output


def compute_trace_depth_budget(
    rooted_call_graphs: Dict[str, Dict[str, List[str]]],
    entry_func: str,
) -> int:
    """Return an adaptive function-level trace budget for one analysis root."""
    if TRACE_CALLEE_DEPTH < 0:
        return -1
    if TRACE_CALLEE_DEPTH == 0:
        return 0
    if not TRACE_ADAPTIVE or TRACE_CALLEE_DEPTH_MAX <= TRACE_CALLEE_DEPTH:
        return TRACE_CALLEE_DEPTH

    largest_reachable_subgraph = 0
    for root, graph in rooted_call_graphs.items():
        contains_entry = (
            entry_func == root
            or entry_func in graph
            or any(entry_func in (callees or []) for callees in graph.values())
        )
        if not contains_entry:
            continue

        reachable: Set[str] = set()
        queue: deque[str] = deque([entry_func])
        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            for callee in graph.get(current, []) or []:
                if callee not in reachable:
                    queue.append(callee)
        largest_reachable_subgraph = max(
            largest_reachable_subgraph, len(reachable)
        )

    if largest_reachable_subgraph == 0:
        return TRACE_CALLEE_DEPTH
    if largest_reachable_subgraph < TRACE_CALLEE_DEPTH:
        return TRACE_CALLEE_DEPTH_MAX
    if largest_reachable_subgraph <= TRACE_CALLEE_DEPTH_MAX:
        return min(TRACE_CALLEE_DEPTH_MAX, TRACE_CALLEE_DEPTH + 1)
    return TRACE_CALLEE_DEPTH


def extract_function_name_from_string(code_line: str) -> Optional[str]:
    if not isinstance(code_line, str):
        return None
    keywords = {"if", "while", "for", "switch", "catch", "return", "sizeof"}
    pattern = r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\("
    for match in re.finditer(pattern, code_line):
        name = match.group(1)
        if name not in keywords:
            return name
    return None


def get_argument_positions(
    statement: str,
    target_func_name: str,
    source_variables: Sequence[str],
) -> List[int]:
    """Return all argument positions containing any alias of the source."""
    try:
        match = re.search(r"\b" + re.escape(target_func_name) + r"\s*\(", statement)
        if not match:
            return []
        content_start = match.end()
        depth = 1
        content_end = -1
        for offset, char in enumerate(statement[content_start:]):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            if depth == 0:
                content_end = content_start + offset
                break
        if content_end < 0:
            return []

        args_blob = statement[content_start:content_end]
        args: List[str] = []
        current: List[str] = []
        depth = 0
        for char in args_blob:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(0, depth - 1)
            if char == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        args.append("".join(current).strip())

        variables = [v for v in source_variables if v and re.match(r"^[A-Za-z_]\w*$", v)]
        positions: List[int] = []
        for index, argument in enumerate(args):
            if any(re.search(rf"\b{re.escape(var)}\b", argument) for var in variables):
                positions.append(index)
        return positions
    except Exception:
        return []


def _choose_alias_used(operation: str, aliases: Sequence[str]) -> str:
    for alias in sorted(set(aliases), key=len, reverse=True):
        if alias and re.search(rf"\b{re.escape(alias)}\b", operation or ""):
            return alias
    return sorted(set(aliases))[0] if aliases else "[unknown]"


def _source_identity(
    root_func: str,
    aliases: Sequence[str],
    taint_sources: Sequence[str],
    source_from_functions: Sequence[str],
    path_kind: str,
    abstract_object: Optional[str] = None,
    parameter_index: Optional[int] = None,
) -> str:
    """
    Stable source identity. Variable spelling is not the primary key because aliases
    should not create duplicate source groups.
    """
    payload = {
        "root": root_func,
        "path_kind": path_kind,
        "sources": sorted(_normalize_code(x) for x in taint_sources if x),
        "source_functions": sorted(x for x in source_from_functions if x),
        "abstract_object": abstract_object or "",
        "parameter_index": parameter_index,
    }
    # Declaration fallback may be identical for unrelated variables. Include the
    # alias set only when no stronger origin information exists.
    if not payload["sources"]:
        payload["aliases"] = sorted(set(aliases))
    return _stable_hash(payload, 24)


def _source_display(aliases: Sequence[str], abstract_object: Optional[str] = None) -> str:
    # Input arrives root-segment-first (see _source_group_metadata); keep that
    # order and cap long lists: the header only needs the origin names, the
    # per-hop names are rendered in their own path sections. Display-only —
    # argument matching and source identity use per-segment alias sets.
    aliases = _dedup_preserve_order(str(a) for a in aliases if a)
    if abstract_object:
        return f"{aliases[0] if aliases else '[object]'} @ {abstract_object}"
    if not aliases:
        return "[unknown source]"
    if len(aliases) == 1:
        return aliases[0]
    shown = aliases[:5]
    suffix = f", +{len(aliases) - len(shown)} more" if len(aliases) > len(shown) else ""
    return f"{shown[0]} (aliases: {', '.join(shown[1:])}{suffix})"


def _extract_json_candidates(raw_text: str) -> List[Any]:
    text = (raw_text or "").strip()
    if not text:
        return []
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
    text = re.sub(r"\s*```$", "", text)

    candidates: List[Tuple[int, int, Any]] = []
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, consumed = decoder.raw_decode(text[index:])
            candidates.append((index, consumed, value))
        except json.JSONDecodeError:
            continue
    # Prefer the largest/outermost JSON document. Nested objects are still returned
    # afterwards for tolerant recovery, but parsers must explicitly validate their
    # container shape before accepting them.
    candidates.sort(key=lambda item: (-item[1], item[0]))
    output: List[Any] = []
    seen: Set[str] = set()
    for _, _, value in candidates:
        marker = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(value)
    return output


def _parse_screening_result(raw_text: str) -> ScreeningResult:
    errors: List[str] = []
    for candidate in _extract_json_candidates(raw_text):
        payload = candidate
        if isinstance(payload, list):
            payload = {"hypotheses": payload}
        if isinstance(payload, dict):
            recognized_container = "hypotheses" in payload
            if "hypotheses" not in payload:
                for alias in ("vulnerable_paths", "vulnerabilities", "results", "findings"):
                    if alias in payload and (isinstance(payload[alias], list) or payload[alias] is None):
                        payload = {"hypotheses": payload[alias]}
                        recognized_container = True
                        break
            # Do not accept a nested hypothesis object as an empty ScreeningResult.
            if not recognized_container:
                continue
            if payload.get("hypotheses") is None:
                errors.append("Screening hypotheses container is null")
                continue
            # Some local models emit JSON null for optional-looking string fields.
            # Normalize those values before Pydantic validation.
            if isinstance(payload.get("hypotheses"), list):
                normalized_hypotheses = []
                for hypothesis in payload["hypotheses"]:
                    if not isinstance(hypothesis, dict):
                        continue
                    item = dict(hypothesis)
                    for field_name in (
                        "hypothesis_id",
                        "potential_vulnerability_type",
                        "cwe_id",
                        "root_cause_hypothesis",
                        "suspected_broken_control",
                        "security_boundary_assumption",
                    ):
                        if item.get(field_name) is None:
                            item[field_name] = ""
                    for field_name in (
                        "required_preconditions",
                        "relevant_source_ids",
                        "relevant_subpath_ids",
                        "relevant_fact_ids",
                        "relevant_sink_ids",
                    ):
                        if item.get(field_name) is None:
                            item[field_name] = []
                    normalized_hypotheses.append(item)
                payload["hypotheses"] = normalized_hypotheses
            try:
                return _model_validate(ScreeningResult, payload)
            except Exception as exc:
                errors.append(str(exc))
    raise ValueError("No valid ScreeningResult JSON found" + (f": {errors[-1]}" if errors else ""))


def _normalize_vulnerability_status(value: Any) -> Optional[str]:
    """Return a canonical binary verdict, or None when the model omitted it."""
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized or normalized in {"n/a", "na", "unknown", "null", "none", "undetermined"}:
        return None
    if normalized in {"vulnerable", "confirmed", "true", "yes", "1"}:
        return "Vulnerable"
    if normalized in {"not vulnerable", "not_vulnerable", "rejected", "false", "no", "0", "safe"}:
        return "Not Vulnerable"
    return None


def _canonical_hypothesis_id(value: Any, expected_ids: Sequence[str]) -> str:
    """Normalize common model variants such as `h1`, `H-1`, or `Hypothesis 1`."""
    text = str(value or "").strip()
    if not text:
        return ""
    expected_lookup = {item.upper(): item for item in expected_ids}
    compact = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    if compact in expected_lookup:
        return expected_lookup[compact]
    match = re.search(r"(?:HYPOTHESIS|H)?\s*[-_:#]*\s*(\d+)", text, flags=re.I)
    if match:
        candidate = f"H{int(match.group(1))}"
        if not expected_ids or candidate in expected_ids:
            return candidate
    return text


def _verification_findings_list(payload: Any) -> Optional[List[Dict[str, Any]]]:
    """Accept list, alias containers, ID-keyed dictionaries, or one finding object."""
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return None

    container: Any = payload.get("findings")
    if container is None:
        for alias in ("results", "decisions", "verdicts"):
            if alias in payload:
                container = payload[alias]
                break

    if isinstance(container, list):
        return [dict(item) for item in container if isinstance(item, dict)]
    if isinstance(container, dict):
        result: List[Dict[str, Any]] = []
        for key, value in container.items():
            if not isinstance(value, dict):
                continue
            item = dict(value)
            item.setdefault("hypothesis_id", key)
            result.append(item)
        return result

    # Some models return {"H1": {...}, "H2": {...}} directly.
    id_keyed = []
    for key, value in payload.items():
        if isinstance(value, dict) and re.search(r"(?:hypothesis|h)?\s*[-_:#]*\s*\d+", str(key), flags=re.I):
            item = dict(value)
            item.setdefault("hypothesis_id", key)
            id_keyed.append(item)
    if id_keyed:
        return id_keyed

    # One-hypothesis retry may return the finding object directly.
    if any(key in payload for key in ("is_vulnerable", "verdict", "vulnerability_root_cause", "reasoning")):
        return [dict(payload)]
    return None


def _parse_verification_result(
    raw_text: str,
    expected_ids: Sequence[str] = (),
) -> VerificationResult:
    errors: List[str] = []
    for candidate in _extract_json_candidates(raw_text):
        findings = _verification_findings_list(candidate)
        if findings is None:
            continue

        normalized_findings: List[Dict[str, Any]] = []
        for finding in findings:
            item = dict(finding)
            raw_id = item.get(
                "hypothesis_id",
                item.get("hypothesisId", item.get("hypothesis", item.get("id", ""))),
            )
            item["hypothesis_id"] = _canonical_hypothesis_id(raw_id, expected_ids)
            normalized_status = _normalize_vulnerability_status(
                item.get("is_vulnerable", item.get("verdict"))
            )
            # A missing/unknown verdict is not evidence of rejection. Leave the
            # hypothesis unresolved so the retry path can re-verify it.
            if normalized_status is None:
                errors.append(
                    f"Missing/unknown is_vulnerable for hypothesis {item.get('hypothesis_id') or '[unmapped]'}"
                )
                continue
            item["is_vulnerable"] = normalized_status
            if "vulnerability_root_cause" not in item:
                item["vulnerability_root_cause"] = item.get(
                    "root_cause", item.get("reasoning", item.get("reason", ""))
                )
            if "vulnerable_path" not in item:
                item["vulnerable_path"] = item.get("path", "N/A")
            if "cwe_id" not in item:
                item["cwe_id"] = item.get("cwe", "N/A")
            if "vulnerability_type" not in item:
                item["vulnerability_type"] = item.get("type", "N/A")
            if "security_boundary" not in item:
                item["security_boundary"] = item.get("trust_boundary", "Unknown")
            if "boundary_status" not in item:
                item["boundary_status"] = item.get("security_boundary_status", "Unknown")
            item["counterevidence"] = _normalize_string_list(
                item.get("counterevidence", item.get("counter_evidence"))
            )
            item["defenses_considered"] = _normalize_string_list(
                item.get("defenses_considered")
            )
            item["proof_gaps"] = _normalize_string_list(
                item.get("proof_gaps", item.get("evidence_gaps"))
            )
            item["evidence_requests"] = _normalize_evidence_requests(
                item.get("evidence_requests", item.get("requested_evidence"))
            )
            # LLMs often use null for unknown metadata. Convert it before model
            # validation so a valid verdict is not discarded as a parse failure.
            for field_name, default in (
                ("hypothesis_id", ""),
                ("vulnerability_type", "N/A"),
                ("cwe_id", "N/A"),
                ("vulnerability_root_cause", "No reasoning supplied."),
                ("vulnerable_path", "N/A"),
                ("security_boundary", "Unknown"),
                ("boundary_status", "Unknown"),
                ("confidence", "Medium"),
            ):
                if item.get(field_name) is None:
                    item[field_name] = default
            normalized_findings.append(item)

        # If the model returned exactly one finding per expected hypothesis but omitted
        # the IDs, preserve its declared order and assign IDs locally. Only findings
        # with a BLANK id are eligible: a finding carrying a non-empty id that cannot
        # be canonicalized to an expected hypothesis refers to something else, and
        # attaching it positionally would fabricate a verdict for the wrong
        # hypothesis.
        if expected_ids:
            for item in normalized_findings:
                canonical = _canonical_hypothesis_id(item.get("hypothesis_id"), expected_ids)
                if canonical in expected_ids:
                    item["hypothesis_id"] = canonical
            valid_seen = {
                item["hypothesis_id"]
                for item in normalized_findings
                if item.get("hypothesis_id") in expected_ids
            }
            missing = [item for item in expected_ids if item not in valid_seen]
            unmapped = [
                item for item in normalized_findings
                if item.get("hypothesis_id") not in expected_ids
                and not str(item.get("hypothesis_id") or "").strip()
            ]
            if unmapped and len(unmapped) == len(missing):
                for item, expected_id in zip(unmapped, missing):
                    item["hypothesis_id"] = expected_id

        try:
            return _model_validate(VerificationResult, {"findings": normalized_findings})
        except Exception as exc:
            errors.append(str(exc))
    raise ValueError("No valid VerificationResult JSON found" + (f": {errors[-1]}" if errors else ""))


def _json_schema_example_screening() -> str:
    # Category-neutral output contract. Native structured output already
    # receives the full response schema with the request, so the prompt only
    # names the fields; the parser fallback gets a compact JSON skeleton.
    # A concrete vulnerability-class example is deliberately NOT used, to avoid
    # anchoring the model to any one CWE label.
    if _SCREENING_NATIVE is not None:
        return (
            "Return one JSON object conforming to the response schema supplied with this "
            "request: a `hypotheses` array; return an empty list when no credible "
            "hypothesis is supported. Each hypothesis provides hypothesis_id (H1, H2, ...), "
            "potential_vulnerability_type, cwe_id, root_cause_hypothesis, "
            "suspected_broken_control, required_preconditions, "
            "security_boundary_assumption, and the cited-ID arrays relevant_source_ids, "
            "relevant_subpath_ids, relevant_fact_ids, relevant_sink_ids."
        )
    return (
        "Return JSON only (no commentary, no markdown fences) with this shape:\n"
        '{"hypotheses": [{"hypothesis_id": "H1", "potential_vulnerability_type": "...", '
        '"cwe_id": "CWE-### or N/A", "root_cause_hypothesis": "...", '
        '"suspected_broken_control": "...", "required_preconditions": ["..."], '
        '"security_boundary_assumption": "... or Unknown", '
        '"relevant_source_ids": ["SRC1"], "relevant_subpath_ids": ["SP1"], '
        '"relevant_fact_ids": ["F1"], "relevant_sink_ids": ["SP1-S1"]}]}\n'
        "Cite only IDs listed in this prompt; use an empty hypotheses list when no "
        "credible hypothesis is supported."
    )


def _json_schema_example_verification(expected_ids: Sequence[str] = ("H1",)) -> str:
    ids = list(expected_ids) or ["H1"]
    if _VERIFICATION_NATIVE is not None:
        contract = (
            "Return one JSON object conforming to the response schema supplied with this "
            "request: a `findings` array. Each finding provides hypothesis_id, "
            "is_vulnerable (exactly \"Vulnerable\" or \"Not Vulnerable\"), "
            "vulnerability_type, cwe_id, vulnerability_root_cause, vulnerable_path, "
            "security_boundary, boundary_status (Established, Plausible, or Unknown), "
            "nullable_origin_kind (null-dereference claims only), counterevidence, "
            "defenses_considered (each recorded entity-referencing condition considered, "
            "with the reason it cannot block the violation), "
            "proof_gaps, evidence_requests (only for an exact missing function or macro "
            "identifier), and confidence (High, Medium, or Low)."
        )
    else:
        contract = (
            "Return JSON only (no commentary, no markdown fences) with this shape:\n"
            '{"findings": [{"hypothesis_id": "H1", '
            '"is_vulnerable": "Vulnerable | Not Vulnerable", '
            '"vulnerability_type": "...", "cwe_id": "CWE-### or N/A", '
            '"vulnerability_root_cause": "...", "vulnerable_path": "...", '
            '"security_boundary": "... or Unknown", '
            '"boundary_status": "Established | Plausible | Unknown", '
            '"nullable_origin_kind": "explicit_null_assignment | nullable_call_result | '
            'conditional_uninitialized | optional_field | hypothetical_caller | unknown", '
            '"counterevidence": ["..."], "defenses_considered": ["..."], '
            '"proof_gaps": ["..."], '
            '"evidence_requests": [{"gap_type": "missing_function_body | '
            'unresolved_call_target | missing_macro_definition | unknown_source_origin | '
            'unknown_capacity_or_extent | unknown_alias_or_object_identity | '
            'unknown_branch_compatibility | missing_control_context | '
            'external_runtime_semantics | other", "symbol": "exact_identifier", '
            '"reason": "..."}], "confidence": "High | Medium | Low"}]}\n'
            "Use empty lists for counterevidence, defenses_considered, proof_gaps, "
            "and evidence_requests when none apply."
        )
    return (
        contract
        + "\nThe findings list must contain exactly one item for each required ID, in this order: "
        + json.dumps(ids, ensure_ascii=False)
    )


def _guard_fact_annotation(fact: Dict[str, Any]) -> str:
    """Compact structured suffix for one guard dictionary entry."""
    parts: List[str] = []
    predicate = _guard_predicate_text(fact.get("normalized"))
    if predicate:
        parts.append(f"effective: {predicate}")
    kind = str(fact.get("kind") or "")
    if kind:
        parts.append(kind)
    roles = fact.get("objects", {}).get("roles") if isinstance(fact.get("objects"), dict) else None
    if roles:
        parts.append("roles: " + ", ".join(f"{var}={role}" for var, role in sorted(roles.items())))
    return " | ".join(parts)


def _guard_predicate_text(normalized: Any) -> Optional[str]:
    """Render a normalized guard predicate as compact text; None when absent."""
    if not isinstance(normalized, dict):
        return None
    logic = normalized.get("logic")
    if logic:
        parts: List[str] = []
        for sub in _safe_list(normalized.get("operands")):
            if isinstance(sub, dict) and sub.get("unparsed"):
                raw = sub.get('raw', '?')
                parts.append(f"!({raw})" if sub.get("negated") else f"({raw})")
                continue
            text = _guard_predicate_text(sub)
            parts.append(f"({text})" if text else "(?)")
        return f" {logic} ".join(parts)
    lhs, op, rhs = normalized.get("lhs"), normalized.get("op"), normalized.get("rhs")
    if not lhs or not op:
        return None
    if isinstance(rhs, list):
        rhs = "{" + ", ".join(str(item) for item in rhs) + "}"
    return f"{lhs} {op} {rhs}"


def _prompt_facts_for_subpath(subpath: SourceSubpath) -> List[Dict[str, Any]]:
    """Return every path-spine fact while avoiding terminal-operation duplication.

    A terminal operation is already represented, with controls and source identity, in
    the sink table. Omitting its duplicate FACT rendering does not remove any path or
    sink evidence; it only prevents the same operation from appearing twice.
    """
    return [
        fact for fact in subpath.facts
        if str(fact.get("event_kind") or "") != "TERMINAL_OPERATION"
        and (
            _safe_list(fact.get("supported_sink_ids"))
            or not _safe_list(fact.get("supported_sink_keys"))
        )
    ]


def _balanced_region(
    text: str,
    opening_index: int,
    opening: str,
    closing: str,
) -> Optional[Tuple[int, int]]:
    """Return a balanced region while ignoring delimiters inside literals."""
    if opening_index < 0 or opening_index >= len(text) or text[opening_index] != opening:
        return None
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening_index, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return opening_index, index
    return None


def _meaningful_label(value: Any) -> str:
    normalized = _normalize_space(str(value or "")).upper()
    if normalized in {"", "N/A", "NA", "NONE", "NULL", "UNKNOWN", "UNSPECIFIED"}:
        return ""
    return normalized


def _call_arguments(operation: str, function_name: str) -> List[str]:
    match = re.search(rf"\b{re.escape(function_name)}\s*\(", operation)
    if match is None:
        return []
    opening = operation.find("(", match.start())
    region = _balanced_region(operation, opening, "(", ")")
    if region is None:
        return []
    return _split_call_arguments(operation[opening + 1:region[1]])


def _split_call_arguments(argument_text: str) -> List[str]:
    parts: List[str] = []
    start = 0
    paren = bracket = brace = 0
    quote = ""
    escaped = False
    for index, char in enumerate(argument_text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
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
        elif char == "," and not (paren or bracket or brace):
            parts.append(argument_text[start:index].strip())
            start = index + 1
    parts.append(argument_text[start:].strip())
    return parts


def _target_function_code(task: MultiSourcePathTask) -> str:
    marker = f"// Analysis Target Function: {task.target_function}\n"
    marker_start = task.code_context.find(marker)
    if marker_start < 0:
        return ""
    body_start = marker_start + len(marker)
    next_header = re.search(r"\n// [^\n]*Function: ", task.code_context[body_start:])
    body_end = body_start + next_header.start() if next_header else len(task.code_context)
    return task.code_context[body_start:body_end]


def _source_sink_marker(
    subpath: SourceSubpath,
    sink: Dict[str, Any],
    source_task_id: Optional[str] = None,
) -> str:
    return json.dumps({
        "source_task_id": source_task_id or subpath.source_task_id,
        "function": sink.get("function"),
        "start_byte": sink.get("start_byte", -1),
        "operation": _normalize_code(sink.get("operation")),
        "type": sink.get("type"),
        "abstract_object": sink.get("abstract_object"),
    }, sort_keys=True, ensure_ascii=False)

"""Pydantic structured-output models and parser/structured-output builders."""

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
    OutputFixingParser,
    PydanticOutputParser,
    STRUCTURED_OUTPUT_MODE,
    USE_OUTPUT_FIXING_PARSER,
    _analyzer_chat_llm,
    _analyzer_text_llm,
    _screener_chat_llm,
    _screener_text_llm,
)


class RootCauseHypothesis(BaseModel):
    # Metadata fields tolerate null because local models sometimes emit null for
    # unknown optional-looking values. Semantic normalization still occurs before use.
    hypothesis_id: Optional[str] = Field(default="", description="Unique ID supplied by the model, e.g. H1.")
    potential_vulnerability_type: Optional[str] = Field(default="N/A", description="Potential vulnerability type.")
    cwe_id: Optional[str] = Field(default="N/A", description="Likely CWE ID, or N/A.")
    root_cause_hypothesis: Optional[str] = Field(
        default="",
        description="Concrete root-cause hypothesis for this exact-path operation component.",
    )
    suspected_broken_control: Optional[str] = Field(
        default="",
        description="Missing, insufficient, or bypassed code-level control implicated by the hypothesis.",
    )
    required_preconditions: Optional[List[str]] = Field(default_factory=list)
    security_boundary_assumption: Optional[str] = Field(
        default="Unknown",
        description="Why the source is security relevant, or Unknown when the supplied context cannot establish it.",
    )
    relevant_source_ids: Optional[List[str]] = Field(default_factory=list)
    relevant_subpath_ids: Optional[List[str]] = Field(default_factory=list)
    relevant_fact_ids: Optional[List[str]] = Field(default_factory=list)
    relevant_sink_ids: Optional[List[str]] = Field(default_factory=list)


class ScreeningResult(BaseModel):
    hypotheses: List[RootCauseHypothesis] = Field(default_factory=list)


class EvidenceRequest(BaseModel):
    gap_type: Optional[str] = Field(
        default="other",
        description=(
            "One of missing_function_body, unresolved_call_target, missing_macro_definition, "
            "unknown_source_origin, unknown_capacity_or_extent, unknown_alias_or_object_identity, "
            "unknown_branch_compatibility, missing_control_context, external_runtime_semantics, or other."
        ),
    )
    symbol: Optional[str] = Field(
        default="",
        description="Exact function or macro identifier whose definition could resolve the gap, if known.",
    )
    reason: Optional[str] = Field(default="")


class HypothesisFinding(BaseModel):
    # Only the binary verdict is strict. Other metadata can be null and is normalized
    # locally, preventing a valid verdict from being discarded by Pydantic.
    hypothesis_id: Optional[str] = ""
    is_vulnerable: Literal["Vulnerable", "Not Vulnerable"]
    vulnerability_type: Optional[str] = "N/A"
    cwe_id: Optional[str] = "N/A"
    vulnerability_root_cause: Optional[str] = Field(
        default="No reasoning supplied.",
        description="Violated security invariant and the concrete defective operation or control.",
    )
    vulnerable_path: Optional[str] = Field(
        default="N/A",
        description="Attack path: relevant input, transformations, failed control, terminal operation, and consequence.",
    )
    security_boundary: Optional[str] = Field(
        default="Unknown",
        description="Trust or product boundary that makes the input and outcome security relevant.",
    )
    boundary_status: Optional[str] = Field(
        default="Unknown",
        description="Established, Plausible, or Unknown.",
    )
    nullable_origin_kind: Optional[str] = Field(
        default="",
        description=(
            "For null-dereference claims only: the concrete nullable origin category — "
            "explicit_null_assignment, nullable_call_result, conditional_uninitialized, "
            "optional_field, hypothetical_caller, or unknown."
        ),
    )
    counterevidence: Optional[List[str]] = Field(default_factory=list)
    defenses_considered: List[str] = Field(
        description=(
            "REQUIRED (use [] only when no entity-referencing conditions were "
            "shown): each recorded entity-referencing condition considered before "
            "the verdict, with the concrete reason it cannot block the violation "
            "(dominance, path compatibility, entity alignment, or property scope). "
            "Record only; never used for filtering."
        ),
    )
    proof_gaps: Optional[List[str]] = Field(default_factory=list)
    evidence_requests: Optional[List[EvidenceRequest]] = Field(default_factory=list)
    confidence: Optional[str] = Field(default="Medium", description="High, Medium, or Low.")


class VerificationResult(BaseModel):
    findings: List[HypothesisFinding] = Field(default_factory=list)


PUBLIC_FINDING_FIELDS = (
    "is_vulnerable",
    "vulnerability_type",
    "cwe_id",
    "vulnerability_root_cause",
    "vulnerable_path",
    "security_boundary",
    "boundary_status",
    "counterevidence",
    "defenses_considered",
    "proof_gaps",
    "confidence",
)


def _build_pydantic_parser(model_cls: Any) -> Any:
    if PydanticOutputParser is None:
        return None
    try:
        return PydanticOutputParser(pydantic_object=model_cls)
    except TypeError:
        return PydanticOutputParser(model_cls=model_cls)


def _build_output_fixer(parser: Any, llm: Any) -> Any:
    if not USE_OUTPUT_FIXING_PARSER or OutputFixingParser is None or parser is None or llm is None:
        return None
    try:
        return OutputFixingParser.from_llm(parser=parser, llm=llm)
    except Exception as exc:
        print(f"[Config] OutputFixingParser unavailable: {exc}")
        return None


def _build_native_structured(chat_llm: Any, model_cls: Any) -> Any:
    if chat_llm is None or STRUCTURED_OUTPUT_MODE == "parser":
        return None
    try:
        # Newer langchain-ollama versions accept method='json_schema'. Older versions
        # expose with_structured_output(schema) without the method argument.
        return chat_llm.with_structured_output(model_cls, method="json_schema")
    except TypeError:
        try:
            return chat_llm.with_structured_output(model_cls)
        except Exception as exc:
            if STRUCTURED_OUTPUT_MODE == "native":
                print(f"[Config] Native structured output unavailable: {exc}")
            return None
    except Exception as exc:
        if STRUCTURED_OUTPUT_MODE == "native":
            print(f"[Config] Native structured output unavailable: {exc}")
        return None


_SCREENING_PARSER = _build_pydantic_parser(ScreeningResult)


_VERIFICATION_PARSER = _build_pydantic_parser(VerificationResult)


_SCREENING_FIXER = _build_output_fixer(_SCREENING_PARSER, _screener_text_llm)


_VERIFICATION_FIXER = _build_output_fixer(_VERIFICATION_PARSER, _analyzer_text_llm)


_SCREENING_NATIVE = _build_native_structured(_screener_chat_llm, ScreeningResult)


_VERIFICATION_NATIVE = _build_native_structured(_analyzer_chat_llm, VerificationResult)



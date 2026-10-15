"""Configuration, LLM client construction, and shared runtime handles."""

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



ChatOllama: Any = None


ChatOpenAI: Any = None


LegacyOllama: Any = None


PydanticOutputParser: Any = None


OutputFixingParser: Any = None


try:
    from langchain_ollama import ChatOllama
except ImportError:  # Optional modern integration; legacy LangChain remains supported.
    ChatOllama = None  # type: ignore[assignment]


try:
    from langchain_openai import ChatOpenAI
except ImportError:  # Optional; only needed for OpenAI-compatible backends.
    ChatOpenAI = None  # type: ignore[assignment]


try:
    from langchain_community.llms.ollama import Ollama as LegacyOllama
except ImportError:
    LegacyOllama = None  # type: ignore[assignment]


try:
    from langchain.output_parsers import PydanticOutputParser, OutputFixingParser
except ImportError:
    try:
        from langchain_core.output_parsers import PydanticOutputParser
    except ImportError:
        PydanticOutputParser = None  # type: ignore[assignment]
    try:
        from langchain_classic.output_parsers import OutputFixingParser
    except ImportError:
        OutputFixingParser = None  # type: ignore[assignment]










try:
    # tree-sitter ships with the static backend; used only to enumerate formal
    # parameters of entry-point roots before seeding parameter sources.
    from tree_sitter import Language as _TSLanguage, Parser as _TSParser
except ImportError:  # pragma: no cover - backend already hard-requires it.
    _TSLanguage = None
    _TSParser = None


_TREE_SITTER_LANGUAGES_SO = os.environ.get(
    "OCEAN_TREE_SITTER_SO", os.environ.get("PCVD_TREE_SITTER_SO",
    "/home/langgraph/tools/tree_sitter/build/my-languages.so"),
)


warnings.filterwarnings("ignore")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        print(f"[Config] Invalid integer {name}={raw!r}; using {default}.")
        return default


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None and value.strip() else default


MODEL_NAME = _env_str("VUL_MODEL", "gpt-oss:120b")


LLM_BACKEND = _env_str("VUL_LLM_BACKEND", "ollama").strip().lower()


if LLM_BACKEND not in {"ollama", "openai"}:
    print(f"[Config] Unknown VUL_LLM_BACKEND={LLM_BACKEND!r}; using 'ollama'.")
    LLM_BACKEND = "ollama"


OPENAI_BASE_URL = _env_str("VUL_OPENAI_BASE_URL", "https://api.deepseek.com")


# Falls back to DEEPSEEK_API_KEY so a DeepSeek key exported in the shell works
# out of the box when the openai backend is selected.
OPENAI_API_KEY = _env_str(
    "VUL_OPENAI_API_KEY",
    _env_str("DEEPSEEK_API_KEY", ""),
)


OPENAI_TIMEOUT = max(30, _env_int("VUL_OPENAI_TIMEOUT", 600))


OLLAMA_BASE_URL = _env_str("VUL_OLLAMA_BASE_URL", "http://localhost:11434")


MODEL_NUM_CTX = _env_int("VUL_NUM_CTX", 65536)


SCREENER_NUM_PREDICT = _env_int("VUL_SCREENER_NUM_PREDICT", 8192)


ANALYZER_NUM_PREDICT = _env_int("VUL_ANALYZER_NUM_PREDICT", 8192)


ANALYZER_MISSING_BATCH_RETRY = _env_bool("VUL_ANALYZER_MISSING_BATCH_RETRY", True)


ANALYZER_MISSING_SINGLE_RETRY = _env_bool("VUL_ANALYZER_MISSING_SINGLE_RETRY", True)


PROOF_GAP_EXPANSION = _env_bool("VUL_PROOF_GAP_EXPANSION", True)


EVIDENCE_SOURCE_ROOTS = tuple(
    os.path.abspath(path)
    for path in _env_str("VUL_EVIDENCE_ROOTS", "").split(os.pathsep)
    if path.strip() and os.path.exists(path)
)


MAX_EVIDENCE_SYMBOL_FILES = max(
    1, _env_int("VUL_MAX_EVIDENCE_SYMBOL_FILES", 20)
)


MAX_PROOF_GAP_SYMBOLS = max(0, _env_int("VUL_MAX_PROOF_GAP_SYMBOLS", 3))


MAX_PROOF_GAP_EVIDENCE_CHARS = max(
    0, _env_int("VUL_MAX_PROOF_GAP_EVIDENCE_CHARS", 16384)
)


MODEL_KEEP_ALIVE = _env_str("VUL_MODEL_KEEP_ALIVE", "8h")


MAX_LLM_CONCURRENCY = max(1, _env_int("VUL_MAX_LLM_CONCURRENCY", 1))


MAX_HYPOTHESES_PER_VERIFICATION = max(
    1, _env_int("VUL_MAX_HYPOTHESES_PER_VERIFICATION", 2)
)


MAX_OPERATIONS_PER_SCREENING_TASK = max(
    1, _env_int("VUL_MAX_OPERATIONS_PER_SCREENING_TASK", 16)
)


MAX_PATHS_PER_TARGET_FAMILY = max(
    1, _env_int("VUL_MAX_PATHS_PER_TARGET_FAMILY", 32)
)


MAX_NULLABLE_ORIGIN_PATHS_PER_FILE = max(
    0, _env_int("VUL_MAX_NULLABLE_PATHS", 0)
)


GUARDFACT_PROMPT = _env_bool("VUL_GUARDFACT_PROMPT", True)


VEC_COUNTER_EVIDENCE = _env_bool("VUL_VEC_COUNTER_EVIDENCE", True)


VEC_FAMILIES = frozenset(
    item.strip()
    for item in _env_str("VUL_VEC_FAMILIES", "null,integer,lifetime,bounds").split(",")
    if item.strip()
)


VEC_MAX_ITEMS = max(1, _env_int("VUL_VEC_MAX_ITEMS", 8))


VEC_NULLABILITY_SIGNALS = _env_bool("VUL_VEC_NULLABILITY_SIGNALS", True)


VEC_NULLABILITY_MAX_SITES = max(1, _env_int("VUL_VEC_NULLABILITY_MAX_SITES", 2))


LOAD_BEARING_RULE = _env_bool("VUL_LOAD_BEARING_RULE", True)


ENTITY_CONDITIONS = _env_bool("VUL_ENTITY_CONDITIONS", True)


ENTITY_CONDITIONS_MAX_PER_SINK = max(1, _env_int("VUL_ENTITY_CONDITIONS_MAX_PER_SINK", 6))


ENTITY_CONDITIONS_MAX_RENDER = 8


ENTITY_ALLOCATIONS = _env_bool("VUL_ENTITY_ALLOCATIONS", True)


ENTITY_ALLOCATIONS_MAX_PER_SINK = max(1, _env_int("VUL_ENTITY_ALLOCATIONS_MAX_PER_SINK", 4))


ENTITY_ALLOCATIONS_MAX_RENDER = 4


ENTITY_ALLOCATIONS_FILEWIDE = _env_bool("VUL_ENTITY_ALLOCATIONS_FILEWIDE", True)


ENTITY_CONDITIONS_CALLERS = _env_bool("VUL_ENTITY_CONDITIONS_CALLERS", True)


ENTITY_CONDITIONS_FIELD_FILEWIDE = _env_bool("VUL_ENTITY_CONDITIONS_FIELD_FILEWIDE", True)


CARRIER_EXTENT = _env_bool("VUL_CARRIER_EXTENT", True)


CARRIER_EXTENT_MAX_PER_SINK = max(1, _env_int("VUL_CARRIER_EXTENT_MAX_PER_SINK", 4))


CARRIER_EXTENT_MAX_RENDER = 8


LIFETIME_LINKS = _env_bool("VUL_LIFETIME_LINKS", False)


LIFETIME_LINKS_MAX_PER_FILE = max(1, _env_int("VUL_LIFETIME_LINKS_MAX_PER_FILE", 6))


LIFETIME_LINKS_MAX_PER_TASK = max(1, _env_int("VUL_LIFETIME_LINKS_MAX_PER_TASK", 3))


LIFETIME_LINKS_MAX_SITES = 3


TRACE_CALLEE_DEPTH = _env_int("VUL_TRACE_CALLEE_DEPTH", 4)


TRACE_CALLEE_DEPTH_MAX = max(
    TRACE_CALLEE_DEPTH,
    _env_int("VUL_TRACE_CALLEE_DEPTH_MAX", 6),
) if TRACE_CALLEE_DEPTH >= 0 else -1


TRACE_ADAPTIVE = _env_bool("VUL_TRACE_ADAPTIVE", True)


CONTEXT_CALLER_DEPTH = _env_int("VUL_CONTEXT_CALLER_DEPTH", 0)


CONTEXT_CALLEE_DEPTH = _env_int("VUL_CONTEXT_CALLEE_DEPTH", 1)


MAX_CODE_CONTEXT_CHARS = max(8000, _env_int("VUL_MAX_CODE_CONTEXT_CHARS", 65536))


MAX_TOTAL_PROMPT_CHARS = max(
    MAX_CODE_CONTEXT_CHARS + 8000,
    _env_int("VUL_MAX_TOTAL_PROMPT_CHARS", 131072),
)


MAX_VERIFICATION_PROMPT_CHARS = max(
    MAX_CODE_CONTEXT_CHARS + 8000,
    _env_int("VUL_MAX_VERIFICATION_PROMPT_CHARS", MAX_TOTAL_PROMPT_CHARS),
)


MAX_MACRO_CONTEXT_CHARS = max(0, _env_int("VUL_MAX_MACRO_CONTEXT_CHARS", 16384))


MAX_DECLARATION_CONTEXT_CHARS = max(
    0, _env_int("VUL_MAX_DECLARATION_CONTEXT_CHARS", 8192)
)


MIN_SUPPORT_FUNCTION_CHARS = max(1000, _env_int("VUL_MIN_SUPPORT_FUNCTION_CHARS", 8192))


FOCUSED_CODE_CONTEXT_CHARS = min(
    MAX_CODE_CONTEXT_CHARS,
    max(8000, _env_int("VUL_FOCUSED_CODE_CONTEXT_CHARS", 32768)),
)


MINIMAL_CODE_CONTEXT_CHARS = min(
    MAX_CODE_CONTEXT_CHARS,
    max(6000, _env_int("VUL_MINIMAL_CODE_CONTEXT_CHARS", 16384)),
)


EVIDENCE_ONLY_CODE_CONTEXT_CHARS = min(
    MAX_CODE_CONTEXT_CHARS,
    max(4000, _env_int("VUL_EVIDENCE_ONLY_CODE_CONTEXT_CHARS", 8192)),
)


FALLBACK_MODE = _env_str("VUL_FALLBACK_MODE", "coverage").strip().lower()


if FALLBACK_MODE not in {"always", "coverage", "missing", "off"}:
    print(f"[Config] Unknown VUL_FALLBACK_MODE={FALLBACK_MODE!r}; using 'coverage'.")
    FALLBACK_MODE = "coverage"


FALLBACK_MAX_FACTS = max(0, _env_int("VUL_FALLBACK_MAX_FACTS", 24))


SCREENER_STATIC_RESCUE = _env_bool("VUL_SCREENER_STATIC_RESCUE", False)


PREVERIFY_EXACT_DEDUP = _env_bool("VUL_PREVERIFY_EXACT_DEDUP", True)


LIFECYCLE_EFFECT_SUMMARIES = _env_bool("VUL_LIFECYCLE_EFFECT_SUMMARIES", True)


ALLOW_MODEL_JSON_REPAIR = _env_bool("VUL_ALLOW_MODEL_JSON_REPAIR", True)


USE_OUTPUT_FIXING_PARSER = _env_bool("VUL_USE_OUTPUT_FIXING_PARSER", True)


DEBUG_SCREENER_RAW = _env_bool("VUL_DEBUG_SCREENER_RAW", False)


DEBUG_ANALYZER_RAW = _env_bool("VUL_DEBUG_ANALYZER_RAW", False)


INCLUDE_REJECTED_FINDINGS = _env_bool("VUL_INCLUDE_REJECTED_FINDINGS", False)


SAVE_DIAGNOSTICS = _env_bool("VUL_SAVE_DIAGNOSTICS", True)


FORCE_REPROCESS = _env_bool("VUL_FORCE_REPROCESS", False)


# Native json_schema structured output is an Ollama strength; OpenAI-compatible
# third-party APIs (e.g. DeepSeek) are more reliable with parser-based output.
STRUCTURED_OUTPUT_MODE = _env_str(
    "VUL_STRUCTURED_OUTPUT_MODE",
    "auto" if LLM_BACKEND == "ollama" else "parser",
).strip().lower()


if STRUCTURED_OUTPUT_MODE not in {"auto", "native", "parser"}:
    print(f"[Config] Unknown VUL_STRUCTURED_OUTPUT_MODE={STRUCTURED_OUTPUT_MODE!r}; using 'auto'.")
    STRUCTURED_OUTPUT_MODE = "auto"


MULTI_SOURCE_BATCHING = _env_str("VUL_MULTI_SOURCE_BATCHING", "operation").strip().lower()


if MULTI_SOURCE_BATCHING not in {"operation", "path", "off"}:
    print(f"[Config] Unknown VUL_MULTI_SOURCE_BATCHING={MULTI_SOURCE_BATCHING!r}; using 'operation'.")
    MULTI_SOURCE_BATCHING = "operation"


PATH_VARIANT_BATCHING = _env_str("VUL_PATH_VARIANT_BATCHING", "target").strip().lower()


if PATH_VARIANT_BATCHING not in {"target", "off"}:
    print(f"[Config] Unknown VUL_PATH_VARIANT_BATCHING={PATH_VARIANT_BATCHING!r}; using 'target'.")
    PATH_VARIANT_BATCHING = "target"


SOURCE_GLOB = _env_str(
    "VUL_SOURCE_GLOB",
    "",
)


OUTPUT_DIR = _env_str(
    "VUL_OUTPUT_DIR",
    "./ocean_results",
)


PATCH_SCOPE_ENABLED = _env_bool("VUL_PATCH_SCOPE", True)


DIFF_DIR = _env_str("VUL_DIFF_DIR", "./diffs")


TPT_TREE_ENABLED = _env_bool("VUL_TPT_TREE", True)


SINGLE_STAGE = _env_bool("VUL_SINGLE_STAGE", False)


DIAG_DIR = _env_str("VUL_DIAG_DIR", "") or (OUTPUT_DIR.rstrip(os.sep) + "_diag")


WORKFLOW_NAME = _env_str("VUL_WORKFLOW_NAME", "Vulnerability Detector Ultra")


VERIFIER_STAGE_NAME = _env_str(
    "VUL_VERIFIER_STAGE_NAME",
    "Root-Cause-Consolidated 120B Adversarial Verifier",
)


REVIEW_MODE = _env_str("VUL_REVIEW_MODE", "adversarial").strip().lower()


if REVIEW_MODE not in {"adversarial", "plain"}:
    print(f"[Config] Unknown VUL_REVIEW_MODE={REVIEW_MODE!r}; using 'adversarial'.")
    REVIEW_MODE = "adversarial"


def _make_chat_ollama(num_predict: int) -> Any:
    if ChatOllama is None:
        return None
    return ChatOllama(
        model=MODEL_NAME,
        temperature=0,
        num_ctx=MODEL_NUM_CTX,
        num_predict=num_predict,
        keep_alive=MODEL_KEEP_ALIVE,
        base_url=OLLAMA_BASE_URL,
    )


def _make_chat_openai(num_predict: int) -> Any:
    if ChatOpenAI is None:
        return None
    if not OPENAI_API_KEY:
        raise RuntimeError(
            "VUL_LLM_BACKEND=openai requires an API key: set VUL_OPENAI_API_KEY "
            "or DEEPSEEK_API_KEY."
        )
    return ChatOpenAI(
        model=MODEL_NAME,
        temperature=0,
        max_tokens=num_predict,
        timeout=OPENAI_TIMEOUT,
        max_retries=2,
        base_url=OPENAI_BASE_URL,
        api_key=OPENAI_API_KEY,
    )


def _make_chat_llm(num_predict: int) -> Any:
    if LLM_BACKEND == "openai":
        return _make_chat_openai(num_predict)
    return _make_chat_ollama(num_predict)


def _make_legacy_ollama(num_predict: int) -> Any:
    if LegacyOllama is None:
        return None
    return LegacyOllama(
        model=MODEL_NAME,
        temperature=0,
        num_ctx=MODEL_NUM_CTX,
        num_predict=num_predict,
        keep_alive=MODEL_KEEP_ALIVE,
        base_url=OLLAMA_BASE_URL,
    )


_screener_chat_llm = _make_chat_llm(SCREENER_NUM_PREDICT)


_analyzer_chat_llm = _make_chat_llm(ANALYZER_NUM_PREDICT)


if LLM_BACKEND == "openai":
    # ChatOpenAI.invoke accepts plain strings, so the chat client doubles as
    # the text client; there is no legacy completion fallback for this backend.
    _screener_text_llm = _screener_chat_llm
    _analyzer_text_llm = _analyzer_chat_llm
else:
    _screener_text_llm = _screener_chat_llm or _make_legacy_ollama(SCREENER_NUM_PREDICT)
    _analyzer_text_llm = _analyzer_chat_llm or _make_legacy_ollama(ANALYZER_NUM_PREDICT)


if _screener_text_llm is None or _analyzer_text_llm is None:
    raise ImportError(
        "Install `langchain-ollama` (preferred), `langchain-community`, or "
        "`langchain-openai` (for VUL_LLM_BACKEND=openai) to run the detector."
    )



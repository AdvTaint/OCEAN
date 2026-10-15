"""Internal dataclasses shared across the pipeline."""

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



@dataclass
class AnalysisTask:
    function_name: str
    call_chain: List[str]
    is_transitive_analysis: bool
    accumulated_path: List[Dict[str, Any]] = field(default_factory=list)
    parameter_index: Optional[int] = None
    path_history_context: Optional[str] = None
    abstract_object_hint: Optional[str] = None


@dataclass
class SourcePathTask:
    """One source-specific TPT path ending at one terminal node."""
    task_id: str
    root_func: str
    source_identity: str
    source_display: str
    source_origin: str
    source_defining_func: Optional[str]
    context_mode: str
    source_status: str
    call_chain: List[str]
    target_function: str
    facts: List[Dict[str, Any]]
    sinks: List[Dict[str, Any]]
    call_graph_diagnostics: Dict[str, Any]
    exact_call_edges: List[str] = field(default_factory=list)


@dataclass
class SourceSubpath:
    """Source-specific evidence retained inside a shared exact-call-path LLM task."""
    subpath_id: str
    source_id: str
    source_task_id: str
    source_identity: str
    source_display: str
    source_origin: str
    source_defining_func: Optional[str]
    context_mode: str
    source_status: str
    facts: List[Dict[str, Any]]
    sinks: List[Dict[str, Any]]
    path_root_func: str = ""
    path_call_chain: List[str] = field(default_factory=list)
    path_call_edges: List[str] = field(default_factory=list)


@dataclass
class MultiSourcePathTask:
    """One exact call path/terminal node with one or more independent source subpaths."""
    task_id: str
    root_func: str
    call_chain: List[str]
    target_function: str
    source_subpaths: List[SourceSubpath]
    call_graph_diagnostics: Dict[str, Any]
    exact_call_edges: List[str] = field(default_factory=list)
    batching_mode: str = "operation"
    shared_operation_markers: List[str] = field(default_factory=list)
    code_context: str = ""
    macro_context: str = ""
    selected_caller_depth: int = 0
    selected_callee_depth: int = 0
    code_context_mode: str = "full"
    fact_render_mode: str = "full"
    prompt_chunk_index: int = 1
    prompt_chunk_total: int = 1
    cached_screening_prompt: str = ""
    # Shadow field (never in signatures/grouping): rendered cross-function
    # lifetime-link evidence attached after all task splitting is complete.
    lifetime_link_context: str = ""


@dataclass
class AnalyzerTask:
    path_task: MultiSourcePathTask
    hypotheses: List[Dict[str, Any]]
    cached_verification_prompt: str = ""


@dataclass
class TaintTreeNode:
    function_name: str
    entry_edge_signature: str = "ROOT"
    edge_facts: OrderedDict[str, Dict[str, Any]] = field(default_factory=OrderedDict)
    terminal_sinks: OrderedDict[str, Dict[str, Any]] = field(default_factory=OrderedDict)
    children: OrderedDict[str, "TaintTreeNode"] = field(default_factory=OrderedDict)



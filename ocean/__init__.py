"""OCEAN - Operation-Centered Evidence Composition for LLM-Based Vulnerability Detection.

Two-stage LLM vulnerability detection for C/C++: source-specific taint
propagation trees + operation-aware task batching feed a high-recall
screening stage, followed by adversarial root-cause verification.

Typical usage is through run_detection.py; programmatic entry points below.
"""

from .pipeline import analyze_file, main  # noqa: F401

#!/usr/bin/env python3
"""OCEAN command-line entry point.

All CLI flags map to environment variables consumed by ocean.config, so they
must be set BEFORE the ocean package is imported (config is read at import
time). Anything not passed here keeps its env/default value; see README.md
for the full configuration reference.
"""
from __future__ import annotations

import argparse
import os
import sys


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_detection",
        description=(
            "OCEAN: two-stage (high-recall screening + adversarial verification) "
            "LLM vulnerability detector for C/C++."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    io = parser.add_argument_group("input/output")
    io.add_argument("--source-glob",
                    help="Glob of source files to analyze, e.g. '/data/vul/*.c'. "
                         "Env: VUL_SOURCE_GLOB.")
    io.add_argument("--output-dir",
                    help="Directory for per-file JSON findings. Env: VUL_OUTPUT_DIR.")
    io.add_argument("--diag-dir",
                    help="Directory for per-file diagnostics JSON. "
                         "Default: <output-dir>_diag. Env: VUL_DIAG_DIR.")
    io.add_argument("--diff-dir",
                    help="Directory with patch diffs (<CVE>_diff.txt) for patch-scope "
                         "filtering. Env: VUL_DIFF_DIR.")
    io.add_argument("--no-patch-scope", action="store_true",
                    help="Disable patch-scope filtering (analyze whole files).")

    model = parser.add_argument_group("model")
    model.add_argument("--llm-backend", choices=["ollama", "openai"],
                       help="LLM backend: local Ollama (default) or any "
                            "OpenAI-compatible API (e.g. DeepSeek). Env: VUL_LLM_BACKEND.")
    model.add_argument("--model",
                       help="Model name for BOTH stages (e.g. gpt-oss:120b, "
                            "deepseek-flash). Env: VUL_MODEL.")
    model.add_argument("--ollama-base-url",
                       help="Ollama server URL. Env: VUL_OLLAMA_BASE_URL.")
    model.add_argument("--openai-base-url",
                       help="OpenAI-compatible API base URL "
                            "(default https://api.deepseek.com). Env: VUL_OPENAI_BASE_URL.")
    model.add_argument("--openai-api-key",
                       help="API key for the openai backend. Falls back to env "
                            "VUL_OPENAI_API_KEY or DEEPSEEK_API_KEY.")
    model.add_argument("--num-ctx", type=int,
                       help="Per-request context reservation (tokens). Env: VUL_NUM_CTX.")
    model.add_argument("--concurrency", type=int,
                       help="Client-side parallel LLM requests; the server must run "
                            "with OLLAMA_NUM_PARALLEL >= this value. "
                            "Env: VUL_MAX_LLM_CONCURRENCY.")
    model.add_argument("--review-mode", choices=["adversarial", "plain"],
                       help="Verification style: adversarial (default) or plain "
                            "second-pass review (ablation A4). Env: VUL_REVIEW_MODE.")
    model.add_argument("--single-stage", action="store_true",
                       help="Ablation: skip verification; screening hypotheses are "
                            "the final verdicts. Env: VUL_SINGLE_STAGE=1.")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--tree-sitter-so",
                      help="Path to the tree-sitter language bundle (.so). "
                           "Env: OCEAN_TREE_SITTER_SO.")
    misc.add_argument("--force", action="store_true",
                      help="Reprocess files that already have outputs. "
                           "Env: VUL_FORCE_REPROCESS=1.")
    misc.add_argument("--no-diagnostics", action="store_true",
                      help="Do not write per-file diagnostics. Env: VUL_SAVE_DIAGNOSTICS=0.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    env_map = {
        "VUL_SOURCE_GLOB": args.source_glob,
        "VUL_OUTPUT_DIR": args.output_dir,
        "VUL_DIAG_DIR": args.diag_dir,
        "VUL_DIFF_DIR": args.diff_dir,
        "VUL_LLM_BACKEND": args.llm_backend,
        "VUL_MODEL": args.model,
        "VUL_OLLAMA_BASE_URL": args.ollama_base_url,
        "VUL_OPENAI_BASE_URL": args.openai_base_url,
        "VUL_OPENAI_API_KEY": args.openai_api_key,
        "VUL_REVIEW_MODE": args.review_mode,
        "OCEAN_TREE_SITTER_SO": args.tree_sitter_so,
    }
    for key, value in env_map.items():
        if value is not None:
            os.environ[key] = str(value)
    if args.num_ctx is not None:
        os.environ["VUL_NUM_CTX"] = str(args.num_ctx)
    if args.concurrency is not None:
        os.environ["VUL_MAX_LLM_CONCURRENCY"] = str(args.concurrency)
    if args.no_patch_scope:
        os.environ["VUL_PATCH_SCOPE"] = "0"
    if args.force:
        os.environ["VUL_FORCE_REPROCESS"] = "1"
    if args.single_stage:
        os.environ["VUL_SINGLE_STAGE"] = "1"
    if args.no_diagnostics:
        os.environ["VUL_SAVE_DIAGNOSTICS"] = "0"

    # Deferred import: ocean.config snapshots every knob at import time.
    from ocean.pipeline import main as run
    run()


if __name__ == "__main__":
    sys.exit(main())

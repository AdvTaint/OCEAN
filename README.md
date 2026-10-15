# OCEAN: Operation-Centered Evidence Composition for LLM-Based Vulnerability Detection

OCEAN is a two-stage LLM vulnerability detector for C/C++. A tree-sitter
static backend extracts source-specific propagation evidence and terminal
sink operations, then composes them into **operation-centered evidence
contexts (OCEs)** — all sources reaching the same sensitive operation are
grouped into one analysis task. A high-recall **screening** stage turns each
OCE into root-cause hypotheses; an **adversarial verification** stage then
tries to refute every hypothesis against retrieved counter-evidence before
anything is reported. Output is strictly binary per hypothesis
(`Vulnerable` / `Not Vulnerable`).

## Architecture

```
source file
   │  tree-sitter static analysis (ocean/sast_backend.py)
   ▼
exact source→sink paths ──► prefix-sharing evidence trees (ocean/tpt.py)
   │  alias spellings of one source origin share ONE identity/tree;
   │  same-origin peers reaching the same sink merge into one subpath
   ▼
operation-centered multi-source tasks (ocean/tpt.py, ocean/budget.py)
   │  + deterministic evidence attached as shadow fields (ocean/evidence.py):
   │    entity conditions, allocation/capacity index, carrier extent,
   │    VEC counter-evidence (ocean/vec_retrieval.py)
   ▼
Stage 1 — screening, high recall (ocean/stages.py, prompts in ocean/prompts.py)
   ▼  root-cause hypotheses
Stage 2 — adversarial verification (attacker/defender rubric per CWE family,
   │       bounded proof-gap completion, same model)
   ▼
aggregation by causal fingerprint (ocean/stages.py) ──► per-file JSON findings
```

Module map (`ocean/` package):

| Module | Contents |
|---|---|
| `config.py` | All configuration (env-driven), LLM client construction |
| `schemas.py` | Pydantic output models, parser/structured-output builders |
| `structures.py` | Internal dataclasses (tasks, subpaths, tree nodes) |
| `textutil.py` | Generic text/JSON/normalization helpers |
| `engine.py` | `StaticAnalysisEngine` facade over the tree-sitter backend |
| `tpt.py` | Evidence-tree construction, source grouping, task packing |
| `context.py` | Code-context construction and caching |
| `evidence.py` | Deterministic evidence: entity conditions, carrier extent, lifetime links, VEC attach |
| `prompts.py` | Screening/verification prompt builders and rubric blocks |
| `budget.py` | Prompt-budget degradation and task splitting |
| `stages.py` | Screening/verification invocation, proof-gap completion, aggregation |
| `pipeline.py` | End-to-end per-file pipeline and the main loop |
| `sast_backend.py` | tree-sitter static analysis backend (no LLM) |
| `vec_retrieval.py` | Deterministic counter-evidence retrieval (no LLM) |

## Requirements

- Python ≥ 3.10 (developed on 3.12)
- An [Ollama](https://ollama.com) server with the detection model pulled
  (default `gpt-oss:120b`; a single A100-80G or equivalent is enough)
- A prebuilt tree-sitter language bundle containing the C and C++ grammars

Python packages (see `requirements.txt`):

```
pip install -r requirements.txt
```

### Building the tree-sitter language bundle

The backend loads a combined grammar library (`my-languages.so`). If you do
not have one:

```bash
git clone https://github.com/tree-sitter/tree-sitter-c
git clone https://github.com/tree-sitter/tree-sitter-cpp
python scripts/build_languages.py \
    --grammars tree-sitter-c tree-sitter-cpp \
    --output my-languages.so
```

Point OCEAN at the result with `--tree-sitter-so /path/to/my-languages.so`
(or `export OCEAN_TREE_SITTER_SO=...`; the legacy `PCVD_TREE_SITTER_SO` is
still accepted as a fallback).

### Ollama server

```bash
ollama pull gpt-oss:120b
# Recommended: enable server-side parallelism and flash attention, otherwise
# client-side --concurrency > 1 just queues.
OLLAMA_NUM_PARALLEL=2 OLLAMA_FLASH_ATTENTION=1 ollama serve
```

### OpenAI-compatible backend (e.g. DeepSeek)

Instead of a local Ollama server, OCEAN can run against any OpenAI-compatible
chat API:

```bash
export DEEPSEEK_API_KEY=sk-...          # or pass --openai-api-key
python run_detection.py \
    --llm-backend openai \
    --model deepseek-flash \
    --openai-base-url https://api.deepseek.com \
    --source-glob '/data/targets/*.c' \
    --output-dir results \
    --no-patch-scope --concurrency 6
```

Notes for this backend:

- The API key is read from `--openai-api-key`, `VUL_OPENAI_API_KEY`, or
  `DEEPSEEK_API_KEY` (in that order).
- Structured output automatically switches to parser mode
  (`VUL_STRUCTURED_OUTPUT_MODE=parser`) because third-party APIs do not
  implement Ollama's `json_schema` mode; a tolerant local parser plus an
  output-fixing pass provide the safety net.
- `--concurrency` maps directly to parallel HTTP requests — no server-side
  knob needed, but respect the provider's rate limits.


## Quick start

```bash
python run_detection.py \
    --source-glob '/data/src_code_rebuilt/vul_filter/*.c' \
    --output-dir  results/vul \
    --diff-dir    /data/diff \
    --model       gpt-oss:120b \
    --concurrency 2
```

Each source file produces `<output-dir>/<name>.json` (findings) and
`<output-dir>_diag/<name>.diag.json` (task counts, screened-out tasks,
rejected verdicts, proof gaps — the file never lands in the results dir).
Already-processed files are skipped; pass `--force` to redo them.

### Patch-scope mode (default on)

When `--diff-dir` is given and `<CVE>_diff.txt` exists for a file, only exact
paths whose call chain passes through a patch-touched function are analyzed.
If the diff is missing or no patched function matches, OCEAN falls back to
full-file analysis (a file is never silently skipped). Disable with
`--no-patch-scope`.

## CLI reference

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `--source-glob` | `VUL_SOURCE_GLOB` | — | Source files to analyze |
| `--output-dir` | `VUL_OUTPUT_DIR` | — | Findings output directory |
| `--diag-dir` | `VUL_DIAG_DIR` | `<output>_diag` | Diagnostics directory |
| `--diff-dir` | `VUL_DIFF_DIR` | — | Patch diffs for patch-scope mode |
| `--no-patch-scope` | `VUL_PATCH_SCOPE=0` | on | Analyze whole files |
| `--model` | `VUL_MODEL` | `gpt-oss:120b` | Model for BOTH stages |
| `--llm-backend` | `VUL_LLM_BACKEND` | `ollama` | `ollama` or `openai` (OpenAI-compatible API) |
| `--ollama-base-url` | `VUL_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server |
| `--openai-base-url` | `VUL_OPENAI_BASE_URL` | `https://api.deepseek.com` | OpenAI-compatible API base URL |
| `--openai-api-key` | `VUL_OPENAI_API_KEY` | `$DEEPSEEK_API_KEY` | API key for the openai backend |
| `--num-ctx` | `VUL_NUM_CTX` | `65536` | Per-request context reservation |
| `--concurrency` | `VUL_MAX_LLM_CONCURRENCY` | `1` | Parallel LLM requests (needs server `OLLAMA_NUM_PARALLEL`) |
| `--review-mode` | `VUL_REVIEW_MODE` | `adversarial` | `plain` = ablation A4 (no adversarial framing) |
| `--single-stage` | `VUL_SINGLE_STAGE=1` | off | Ablation: screening-only detector |
| `--tree-sitter-so` | `OCEAN_TREE_SITTER_SO` | (see config.py) | tree-sitter bundle path |
| `--force` | `VUL_FORCE_REPROCESS=1` | off | Reprocess existing outputs |
| `--no-diagnostics` | `VUL_SAVE_DIAGNOSTICS=0` | on | Skip diag JSON files |

Every other knob (prompt budgets, trace depths, evidence retrieval switches,
fallback policy, structured-output mode, …) is an env var documented inline in
`ocean/config.py` — look for the `VUL_*` block comments.

## Output format

Per-file JSON array; each finding carries:

```
is_vulnerable          "Vulnerable" | "Not Vulnerable"   (binary, never "uncertain")
vulnerability_type     free text
cwe_id                 e.g. "CWE-416"
vulnerability_root_cause   violated invariant + defective operation
vulnerable_path        attack path summary
security_boundary / boundary_status
counterevidence / defenses_considered / proof_gaps
confidence             High | Medium | Low
```

## Efficiency notes

- Throughput is dominated by LLM call count × per-call latency. The single
  biggest lever is server-side parallelism: start ollama with
  `OLLAMA_NUM_PARALLEL=2 OLLAMA_FLASH_ATTENTION=1` and pass `--concurrency 2`.
- Operation-centered composition collapses redundant source paths into one
  task per sensitive operation, which is what keeps the LLM call count
  bounded on large files.
- Deterministic evidence (entity conditions, VEC, carrier extent, lifetime
  links) costs zero LLM calls.
- Ablation switches (all default to the main configuration): `VUL_TPT_TREE`,
  `VUL_SINGLE_STAGE`, `VUL_REVIEW_MODE`, `VUL_VEC_COUNTER_EVIDENCE`,
  `VUL_ENTITY_CONDITIONS`, `VUL_CARRIER_EXTENT`, `VUL_LIFETIME_LINKS` (off by
  default), `VUL_LOAD_BEARING_RULE`, `VUL_GUARDFACT_PROMPT`, and more in
  `ocean/config.py`.
- Batching ablations: `VUL_MULTI_SOURCE_BATCHING=off` disables operation-aware
  multi-source grouping; target-function packing then keeps different sources
  in separate prompt tasks while still merging path variants of the same
  source, so only the cross-source joint context is removed. Set
  `VUL_PATH_VARIANT_BATCHING=off` to additionally disable path-variant packing
  itself (one prompt task per exact path).

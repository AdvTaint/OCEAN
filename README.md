# OCEAN: Operation-Centered Evidence Composition for LLM-Based Vulnerability Detection

OCEAN is an LLM-based vulnerability detection framework for C/C++ that combines lightweight static program analysis with operation-centered evidence composition and hypothesis-specific review. Instead of asking an LLM to reconstruct vulnerability-relevant relations from raw source code, OCEAN organizes program evidence around concrete security-sensitive operations and refines that evidence according to each proposed vulnerability mechanism.

OCEAN has two reasoning stages: **hypothesis generation**, which proposes plausible vulnerabilities from operation-centered evidence, and **hypothesis review**, which examines the supporting conditions and potential defenses using hypothesis-specific evidence. The verification stage produces a binary decision for each hypothesis (`Vulnerable` or `Not Vulnerable`), with supporting evidence, considered defenses, and any unresolved proof gaps recorded in the output.

## How OCEAN works

```text
C/C++ source file
    |
    |  Lightweight tree-sitter analysis (ocean/sast_backend.py)
    v
Source-specific evidence paths
    |  source identity, call-site sequence, value-flow/object-state facts,
    |  guard facts, and target sensitive operation
    v
Evidence Path Trees (EPTs) (ocean/tpt.py)
    |  reuse shared call-site prefixes and matching facts
    |  retain path-to-operation target references
    v
Operation-Centered Evidence, OCE(o) (ocean/tpt.py, ocean/context.py)
    |  assemble evidence branches from distinct sources at operation o
    |  preserve each branch's source and calling sequence
    |  include relevant function bodies
    v
Stage 1: Vulnerability hypothesis generation (ocean/stages.py)
    |  proposed mechanism, operation, root cause, and preconditions
    v
Hypothesis-Specific Evidence (HSE) (ocean/evidence.py,
    |                              ocean/vec_retrieval.py, ocean/stages.py)
    |  select mechanism-relevant conditions, bounds, and state updates
    |  incorporate possible counter-evidence and defenses
    v
Stage 2: Hypothesis review (ocean/stages.py, ocean/prompts.py)
    |  assess triggering conditions and effectiveness of defenses
    |  optionally retrieve missing definitions and review once more
    v
Finding aggregation (ocean/stages.py)
    |
    +--> Per-file JSON findings
    +--> Separate diagnostic JSON (tasks, rejections, evidence gaps)
```

### Source-guided path construction

OCEAN uses a tree-sitter-based static backend to identify sources, value-flow and object-state facts, guard conditions, and sensitive operations. It connects these facts into source-specific evidence paths, retaining concrete call-site sequences where calls can be resolved. The analysis is intentionally lightweight and does **not** guarantee complete path or pointer analysis.

### Operation-centered evidence composition

For each source, OCEAN builds an **Evidence Path Tree (EPT)** to reuse overlapping call-site prefixes and matching facts. Target references preserve the associations between shared facts, individual evidence paths, and the sensitive operations they reach. OCEAN then assembles source-specific branches targeting the same concrete operation into **Operation-Centered Evidence (OCE)**, along with relevant function bodies. Branches remain distinguishable by their source identities and call-site sequences rather than being treated as one proven feasible execution path.

### Hypothesis-specific evidence refinement and review

For each generated hypothesis, OCEAN constructs **Hypothesis-Specific Evidence (HSE)** by selecting relevant program constraints, guards, allocation/capacity facts, and object-state updates according to the hypothesized vulnerability mechanism. Candidate facts can be collected deterministically before review; their relevance is determined for the individual hypothesis. The reviewer checks both the proposed triggering conditions and the effectiveness of possible defenses. If critical definitions are missing, bounded proof-gap completion can retrieve additional locally available functions or macros and trigger one further review.

## Repository layout

| Module | Responsibility |
|---|---|
| `ocean/config.py` | Configuration, environment variables, and LLM client setup |
| `ocean/schemas.py` | Structured-output models and parsing |
| `ocean/structures.py` | Internal task, evidence-path, and tree data structures |
| `ocean/textutil.py` | Text, JSON, and normalization utilities |
| `ocean/engine.py` | `StaticAnalysisEngine` facade |
| `ocean/sast_backend.py` | Tree-sitter static analysis backend (no LLM calls) |
| `ocean/tpt.py` | EPT construction, source grouping, and operation-centered assembly |
| `ocean/context.py` | Function-body context construction and caching |
| `ocean/evidence.py` | Deterministic candidate evidence: conditions, capacities, carrier extents, and lifetime-related facts |
| `ocean/vec_retrieval.py` | Deterministic retrieval of potential counter-evidence |
| `ocean/budget.py` | Prompt budgeting, context fallback, and task splitting |
| `ocean/prompts.py` | Hypothesis-generation and review prompts, including vulnerability-mechanism rubrics |
| `ocean/stages.py` | LLM stages, evidence-gap completion, and finding aggregation |
| `ocean/pipeline.py` | End-to-end per-file orchestration |

## Requirements

- Python **3.10 or newer** (developed with Python 3.12).
- The dependencies in `requirements.txt`.
- A compiled tree-sitter language bundle containing the C and C++ grammars.
- An Ollama server with a supported model, or an OpenAI-compatible chat API.

The default model is `gpt-oss:120b`. Its hardware requirements depend on the model format, context length, and concurrency settings; ensure your inference server has sufficient memory.

```bash
pip install -r requirements.txt
```

### Build the tree-sitter language bundle

The backend loads a combined grammar library (`my-languages.so`). If you do not already have one, build it with the included helper:

```bash
git clone https://github.com/tree-sitter/tree-sitter-c
git clone https://github.com/tree-sitter/tree-sitter-cpp
python scripts/build_languages.py \
    --grammars tree-sitter-c tree-sitter-cpp \
    --output my-languages.so
```

Pass its path with `--tree-sitter-so /path/to/my-languages.so` or set `OCEAN_TREE_SITTER_SO`. The legacy environment variable `PCVD_TREE_SITTER_SO` is also accepted as a fallback for existing installations.

### Start an Ollama server

```bash
ollama pull gpt-oss:120b
OLLAMA_NUM_PARALLEL=2 OLLAMA_FLASH_ATTENTION=1 ollama serve
```

Set `--concurrency 2` on the client to permit two concurrent requests. Without corresponding server-side parallelism, requests may queue instead of running simultaneously. Adjust the parallelism and context reservation to your available hardware.

## Quick start

Scan C/C++ source files with OCEAN:

```bash
python run_detection.py \
    --source-glob '/data/targets/*.c' \
    --output-dir results/scan \
    --model gpt-oss:120b \
    --concurrency 2
```

Files matching `--source-glob` are processed individually. Each source file produces a findings JSON file in the output directory and, by default, a corresponding diagnostic file in a separate `<output-dir>_diag/` directory. Existing outputs are skipped; add `--force` to rerun them.

### Use an OpenAI-compatible endpoint

OCEAN can also use an OpenAI-compatible chat endpoint instead of Ollama:

```bash
export DEEPSEEK_API_KEY='YOUR_API_KEY'
python run_detection.py \
    --llm-backend openai \
    --model YOUR_PROVIDER_MODEL_ID \
    --openai-base-url https://api.deepseek.com \
    --source-glob '/data/targets/*.c' \
    --output-dir results/api-scan \
    --concurrency 6
```

Replace `YOUR_PROVIDER_MODEL_ID` with an identifier supported by your endpoint. Credentials are read from `--openai-api-key`, `VUL_OPENAI_API_KEY`, or `DEEPSEEK_API_KEY`, in that order. The OpenAI-compatible backend uses parser-based structured output where the provider does not support Ollama-style JSON-schema responses. Concurrency corresponds to parallel HTTP requests and remains subject to the provider's rate limits.

## Command-line options

| Option | Environment variable | Default | Description |
|---|---|---|---|
| `--source-glob` | `VUL_SOURCE_GLOB` | — | Source files to process |
| `--output-dir` | `VUL_OUTPUT_DIR` | — | Directory for findings JSON |
| `--diag-dir` | `VUL_DIAG_DIR` | `<output>_diag` | Directory for diagnostic JSON |
| `--model` | `VUL_MODEL` | `gpt-oss:120b` | Model used for both reasoning stages |
| `--llm-backend` | `VUL_LLM_BACKEND` | `ollama` | `ollama` or `openai` |
| `--ollama-base-url` | `VUL_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server endpoint |
| `--openai-base-url` | `VUL_OPENAI_BASE_URL` | `https://api.deepseek.com` | OpenAI-compatible API endpoint |
| `--openai-api-key` | `VUL_OPENAI_API_KEY` | `$DEEPSEEK_API_KEY` | API credential |
| `--num-ctx` | `VUL_NUM_CTX` | `65536` | Per-request context reservation |
| `--concurrency` | `VUL_MAX_LLM_CONCURRENCY` | `1` | Maximum concurrent LLM requests |
| `--review-mode` | `VUL_REVIEW_MODE` | `adversarial` | `plain` disables adversarial review framing |
| `--single-stage` | `VUL_SINGLE_STAGE=1` | Off | Run hypothesis generation without the review stage |
| `--tree-sitter-so` | `OCEAN_TREE_SITTER_SO` | See `config.py` | Path to tree-sitter grammar bundle |
| `--force` | `VUL_FORCE_REPROCESS=1` | Off | Reprocess existing outputs |
| `--no-diagnostics` | `VUL_SAVE_DIAGNOSTICS=0` | Diagnostics enabled | Suppress diagnostic JSON |

Additional options for analysis depth, evidence retrieval, prompt budgets, fallback behavior, and structured output are documented in `ocean/config.py` (`VUL_*` variables).

## Output and diagnostics

Each processed source file produces a JSON array of findings. The structured fields include:

| Field | Meaning |
|---|---|
| `is_vulnerable` | Binary decision: `Vulnerable` or `Not Vulnerable` |
| `vulnerability_type`, `cwe_id` | Proposed vulnerability type and CWE |
| `vulnerability_root_cause` | Root-cause explanation and implicated operation |
| `vulnerable_path` | Vulnerability-related propagation or triggering path summary |
| `security_boundary`, `boundary_status` | Evaluated security condition and its status |
| `counterevidence`, `defenses_considered` | Potentially protective or contradictory evidence considered during review |
| `proof_gaps` | Remaining evidence gaps or missing program definitions |
| `confidence` | `High`, `Medium`, or `Low` |

A binary decision does **not** imply that all program facts have been proven. Unresolved evidence may remain in `proof_gaps`. Consult the diagnostic JSON for screened-out tasks, rejected hypotheses, and other intermediate outcomes instead of treating the final findings file as a complete record of all candidates.

## Ablations and configuration switches

The implementation exposes environment-variable switches for controlled comparisons. These names are retained from the codebase, including historical `TPT` and `VEC` names:

| Switch | Purpose |
|---|---|
| `VUL_MULTI_SOURCE_BATCHING=off` | Disable operation-aware assembly across distinct sources |
| `VUL_PATH_VARIANT_BATCHING=off` | Disable packing of same-source path variants into one task |
| `VUL_TPT_TREE` | Enable/disable evidence-tree construction |
| `VUL_SINGLE_STAGE` | Run without the verification stage |
| `VUL_REVIEW_MODE` | Change the review prompt framing |
| `VUL_VEC_COUNTER_EVIDENCE` | Toggle deterministic counter-evidence retrieval |
| `VUL_ENTITY_CONDITIONS` | Toggle additional entity-related conditions |
| `VUL_CARRIER_EXTENT` | Toggle carrier-length and capacity evidence |
| `VUL_LIFETIME_LINKS` | Toggle additional lifetime-link evidence (off by default) |
| `VUL_LOAD_BEARING_RULE` | Toggle the corresponding review rule |
| `VUL_GUARDFACT_PROMPT` | Toggle the corresponding guard-fact prompt features |

Disabling cross-source batching **does not** necessarily disable same-source path sharing or other HSE components. To reproduce a paper ablation, match **all** relevant switches, prompts, model settings, and input conditions to that experiment. Refer to `ocean/config.py` for supported values and defaults.

## Efficiency and scope

- Runtime is generally dominated by LLM inference. Static extraction and candidate-evidence retrieval do not require additional LLM calls, although they can affect prompt size.
- EPT prefix sharing and operation-centered assembly reduce repeated presentation of overlapping evidence. Actual request counts depend on task splitting, evidence budgets, and the number of proposed hypotheses.
- Prompt-budget limits and fallback behavior are configured in `ocean/config.py`.
- OCEAN performs lightweight source-level analysis rather than sound, complete interprocedural verification. In particular, unresolved indirect calls, complex aliasing, and dependencies outside the analyzed source file can leave relevant evidence unavailable.
- Findings remain subject to verification. Treat them as vulnerability reports requiring appropriate triage and responsible disclosure, not as automatically proven exploits.

## Evaluation context

The accompanying research evaluates OCEAN on **InterPVD (497 vulnerable–patched pairs)**, **ReposVul (996 pairs)**, and a collection of **2025–2026 CVEs (189 pairs)**, spanning eight target CWE categories. Its real-world study reports 15 previously unknown vulnerabilities across ten open-source projects, including nine subsequently fixed and three additionally confirmed by maintainers at the time of writing. These results describe the reported evaluation and do not substitute for validating a new deployment or configuration.

# CVEBench construction pipeline

This directory contains the source code used to construct the NPD and UAF
CVEBench benchmarks. It is intentionally source-only. The released benchmark
snapshots are in `../space/code/`; this directory does not include raw CVE
records, cloned repositories, generated task bundles, model outputs, or
historical intermediate results.

The `space/code/` snapshots already contain the accepted vulnerable baseline
implementations. They were generated during benchmark construction with
Qwen3.6-27B-FP8, then retained only after repository validation and independent
LLM judging. Running the released adaptive attacker starts from these
pre-generated baselines; it does not generate them again.

## Pipeline

For each input CVE/function record, the pipeline:

1. clones the repository at the fix commit and checks its build and test suite;
2. extracts the target function, local context, and project headers;
3. asks an LLM to create `task.md` and a stubbed `starter.cc`;
4. asks an attacker model to implement a deliberately vulnerable baseline;
5. splices the implementation into the repository and validates it;
6. uses a separate LLM judge to confirm the intended vulnerability; and
7. assembles the accepted records into detector-ready benchmark snapshots.

The NPD path supports multiple generation rounds; the UAF path uses its
corresponding CWE-416 prompts and builder.

## Inputs and outputs

The scripts accept JSONL input records. They require at least a stable sample
identifier (`pilot_id` or `slug`), repository URL and fix commit, target source
path, target function information, and language. Per-sample files are written
under a caller-selected `samples_cve_fix/` or `samples_cve_uaf/` directory.

`generate_task_only.py` is the task-specification generator. Given extracted
`raw_primary.cc` and optional auxiliary context, it writes `task.md` and
`starter.cc`. It requires an OpenAI-compatible API endpoint and credentials.

`generate_attacker.py` generates the vulnerable baseline after the earlier
viability stages. It uses `config_cve_attacker.yaml` for NPD and
`config_cve_attacker_uaf.yaml` for UAF.

The construction scripts expose command-line help, for example:

```sh
python cvebench/generate_task_only.py --help
python cvebench/check_repo_testsuite.py --help
python cvebench/build_benchmark.py --help
python cvebench/build_benchmark_uaf.py --help
```

## Main scripts

- `filter_pipeline.py`: filters and assigns identifiers to raw CVE records.
- `check_repo_testsuite.py`: repository preparation.
- `extract_context_cve.py`, `extract_headers.py`: source/context extraction.
- `generate_task_only.py`: LLM task-specification generation.
- `generate_attacker.py`, `patch_and_test.py`: vulnerable-baseline generation
  and repository validation.
- `judge_cve_new.py`, `judge_cve_new_uaf.py`: independent LLM judging.
- `build_benchmark.py`, `build_benchmark_uaf.py`: final NPD and UAF assembly.

The pipeline needs Python packages listed in the repository's `pyproject.toml`,
an OpenAI-compatible LLM endpoint for the generation and judging stages,
tree-sitter C/C++ bindings, and the ordinary build dependencies of the cloned
projects.

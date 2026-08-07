# ALIBI artifact

This artifact contains the NPD and UAF benchmarks, result viewer, adaptive
attack code, and defense implementations. Undefended attack traces are
included for both benchmarks.

## Contents

- `space/`: 125 NPD and 70 UAF benchmark snapshots, plus undefended attack
  traces for both benchmarks.
- `adaptive_attacker/`: attack loop, prompts, and detector adapters.
- `adaptive_attacker_uaf/`: UAF attack loop and prompts.
- `benchmark_generation/`: baseline vulnerable-code generator and prompts.
- `defenses/`: defense prompts and comment-screening code.
- `third_party/`: pinned detector sources and local overlay patches.

## Setup

Create the environment for the released attack and defense code with:

```bash
uv sync
```

The detector adapters require their respective upstream implementations, model
weights, and any necessary GPU or API access. The static viewer can be served
from the `space/` directory without model inference.

Run `third_party/setup_detectors.sh` to prepare the pinned detector sources.

## Generating baseline vulnerable code

`benchmark_generation/generate_baseline.py` is the first-stage attacker. Given
a prepared task bundle, it asks a model to fill the function stub with a clean,
deliberately vulnerable implementation. This precedes the adaptive comment
attack; it does not itself validate that the output compiles, passes tests, or
contains the intended vulnerability.

The generator expects a metadata JSONL with one `slug` (or `pilot_id`) per row,
and a matching task directory for each slug containing `task.md` and
`starter.cc`. It also uses `raw_auxiliary.cc` and `raw_headers.h` when present.
For example, to generate all NPD baseline implementations:

```bash
python benchmark_generation/generate_baseline.py task_metadata.jsonl \
  --tasks-dir prepared_tasks --output-dir generated_baselines \
  --config benchmark_generation/config_npd.yaml \
  --model MODEL --base-url http://HOST:PORT/v1 --workers 4
```

This writes `generated_baselines/<slug>/attacker_output.cc`, with the intended
site marked `/* NPD site */`. Use `config_uaf.yaml` for UAF; it marks the unsafe
reuse with `/* UAF site */`. The prepared task bundles and generated outputs are
not included in this artifact.

## NPD attack protocols

The released NPD benchmark snapshots are directly usable through
`--dataset space/code`. The commands below run the selected protocol over all
125 NPD slugs. Each invocation handles one slug, so its output is isolated and
resumable under `adaptive_attacker/results/`.

### Independent, first-flip attack

This is the thorough attack protocol without sharing successful annotations
between presentation types. It stops all remaining types as soon as one type
flips the detector to safe. `--sync round` ensures that all active types in a
round are evaluated before the stopping decision.

```bash
for record in space/code/NPD-CVE-*.json.gz; do
  slug=${record##*/}; slug=${slug%.json.gz}
  python adaptive_attacker/refine_loop_fromscratch.py \
    --detector vulnllmr --dataset space/code --slug "$slug" \
    --budget 5 --sync round --stop-on-any-flip
done
```

### Shared-library, per-type attack

Omit `--stop-on-any-flip` to run every presentation type through its own flip
or the budget. When a type succeeds, its winning annotation is added to an
in-memory library and is shown to the refiner for the still-active types in
later rounds. This is the protocol used for the paper's shared-library
per-type results. With `--sync round`, winners from a round become available
starting in the next round.

```bash
for record in space/code/NPD-CVE-*.json.gz; do
  slug=${record##*/}; slug=${slug%.json.gz}
  python adaptive_attacker/refine_loop_fromscratch.py \
    --detector vulnllmr --dataset space/code --slug "$slug" \
    --budget 5 --sync round
done
```

Results are written under `adaptive_attacker/results/` unless `--out-dir` is
set. The shared-library prompt configuration is
`adaptive_attacker/config_refiner_fromscratch_withlibrary.yaml`; it is chosen
automatically by the second protocol. `--seed-library-system` is separate: it
preloads a library created by a previous run.

## Use-After-Free attack protocol
We also provide the config to show how the attack generalize to UAF.
The 70 attacker generated UAF code are in `space/code/`. To evaluate detectors with UAF bugs, run the following commands with the detector of choice. 

```bash
for record in space/code/UAF-CVE-*.json.gz; do
  slug=${record##*/}; slug=${slug%.json.gz}
  python adaptive_attacker_uaf/refine_loop_uaf.py \
    --detector vulnllmr --dataset space/code --slug "$slug" --budget 5
done
```

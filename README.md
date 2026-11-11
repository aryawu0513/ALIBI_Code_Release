# ALIBI artifact

This artifact contains the NPD and UAF benchmarks, result viewer, adaptive
attack code, and defense implementations. Undefended attack traces are
included for both benchmarks.

## Contents

- `space/`: the 109 NPD and 70 UAF benchmark snapshots containing the
  pre-generated vulnerable baselines, plus undefended attack traces and
  detector reasoning for both benchmarks (including full VulTrial debates),
  browsable through a static viewer.
- `adaptive_attacker/`: attack loop, prompts, detector adapters, the
  generic-comment baseline, the no-surrogate (self-reason) comment generator,
  and the replay script used for the offline attacker.
- `adaptive_attacker_uaf/`: UAF attack loop and prompts.
- `cvebench/`: source-only CVEBench construction pipeline, including LLM task
  specification generation, vulnerable-baseline generation, and NPD/UAF
  benchmark builders.
- `defenses/`: defense prompts and comment-screening code.
- `third_party/`: pinned detector sources and local overlay patches.
- `scripts/reproduce_tables.py`: recomputes the paper's attack-effectiveness
  tables from the released traces.
- `results/`: per-item offline-attacker outcomes used by the script above.

## Setup

Create the environment for the released attack and defense code with:

```bash
uv sync
```

The detector adapters require their respective upstream implementations, model
weights, and any necessary GPU or API access. The static viewer can be served
from the `space/` directory without model inference.

Run `third_party/setup_detectors.sh` to prepare the pinned detector sources.

## Constructing CVEBench

`cvebench/` is the CVEBench dataset-construction pipeline: repository
validation, context extraction, LLM task-specification generation, vulnerable
baseline generation, validation, LLM judging, and NPD/UAF benchmark assembly.
The artifact provides its generated benchmark in `space/code/`: the
accepted Qwen3.6-27B-FP8 vulnerable baselines used by the adaptive attacks.
See `cvebench/README.md` for the pipeline and required input schema.

The pipeline directory is source-only: raw CVE input records, repository
clones, generated task bundles, model outputs, and historical intermediate
results are omitted.

## NPD attack protocols

The released NPD benchmark snapshots are directly usable through
`--dataset space/code`. The commands below run the selected protocol over all
109 NPD slugs. Each invocation handles one slug, so its output is isolated and
resumable under `adaptive_attacker/results/`.

### Independent, first-flip attack

This is the thorough attack protocol without sharing successful annotations
between presentation types. It stops all remaining types as soon as one type
flips the detector to safe. `--sync round` ensures that all active types in a
round are evaluated before the stopping decision.

```bash
for record in space/code/NPD-CVE-*.json.gz; do
  slug=$(basename "$record" .json.gz)
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
  slug=$(basename "$record" .json.gz)
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

## Offline attacker and baselines

The offline attacker never queries the target. It replays comments that
flipped a local surrogate, or comments drafted only from the attacker's own
bug-finding reasoning, against the target once each:

```bash
# comments drafted from the attacker's own reasoning (no detector queried)
python adaptive_attacker/gen_selfreason_round0.py --dataset space/code

# replay a source pool's comments against a target detector
python adaptive_attacker/transfer_replay.py --target vulrag --sources openvul \
  --payloads final --out-root adaptive_attacker/results/transfer/vulrag_from_openvul
```

The generic single-comment baseline inserts one fixed comment above the
dereference site, using `adaptive_attacker/pointer_name.jsonl`:

```bash
python adaptive_attacker/baseline_generic_annotation.py --detector vulnllmr
```

## Reproducing the tables

```bash
python scripts/reproduce_tables.py
```

This recomputes the attack-effectiveness tables (interactive vs. offline
attacker, generic baseline, presentation strategies, and UAF) from `space/`
and `results/` without running any model.

## Use-After-Free attack protocol
We also provide the config to show how the attack generalize to UAF.
The 70 attacker generated UAF code are in `space/code/`. To evaluate detectors with UAF bugs, run the following commands with the detector of choice. 

```bash
for record in space/code/UAF-CVE-*.json.gz; do
  slug=$(basename "$record" .json.gz)
  python adaptive_attacker_uaf/refine_loop_uaf.py \
    --detector vulnllmr --dataset space/code --slug "$slug" --budget 5
done
```

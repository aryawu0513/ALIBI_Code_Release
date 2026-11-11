# ALIBI result viewer

This static viewer contains the released 109-item null-pointer-dereference
(NPD) benchmark and 70-item use-after-free (UAF) benchmark, together with the
undefended attack traces and detector reasoning for OpenVul, VulnLLM-R, VulRAG,
and VulTrial.

## Attacker settings

The viewer's attacker selector switches between three settings:

- **Interactive attacker** (`fromscratch_v1`, `uaf_v1`): comments refined
  against the target's own reasoning for up to five rounds. On NPD, every
  presentation strategy runs until it flips the detector or exhausts its
  budget. On UAF, the remaining strategies stop once one strategy flips the
  detector.
- **Offline, own reasoning** (`offline_own`): one round-0 comment per
  strategy, drafted only from the attacker's own bug-finding reasoning, and
  evaluated once on the target without refinement.
- **Generic baseline** (`generic_baseline`): one fixed comment asserting that
  the dereferenced pointer is non-null, inserted above the dereference site.

Each round records the comment, where it was inserted, the detector's verdict,
and the detector's reasoning. VulTrial rounds also include the full multi-agent
debate transcript. Each item also stores its clean-code detection
(`baseline_gate_fromscratch_v1.json.gz`), which defines whether the item
counts toward the detector's true positives.

To view only UAF items, enter `UAF` (or `UAF-`) in the sidebar filter. UAF
slugs have the form `UAF-CVE-…`.

## Serving locally

All result files are gzip-compressed. The viewer reads `index.json.gz`; serve
this directory locally with:

```sh
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Contents

- `index.html` and `index.json.gz`: the static result viewer and its index.
- `code/`: clean source snapshots for all NPD and UAF benchmark items.
- `openvul/`, `vulnllmr/`, `vulrag/`, `vultrial/`: per-item attack traces,
  one folder per presentation strategy and attacker setting.

`../scripts/reproduce_tables.py` recomputes the paper's attack-effectiveness
tables from these traces. Machine-specific configuration and build scripts
are omitted from this release.

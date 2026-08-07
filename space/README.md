---
title: ALIBI Attacking Code Auditors Via Comments
emoji: 💻
colorFrom: pink
colorTo: gray
sdk: static
pinned: false
---

# ALIBI result viewer

This static viewer contains the released 125-item null-pointer-dereference
(NPD) benchmark and 70-item use-after-free (UAF) benchmark. It also contains
undefended adaptive-attack traces for both benchmarks for OpenVul, VulnLLM-R,
VulRAG, and VulTrial.

## Trace coverage

The NPD traces include both first-flip outcomes and shared-library runs that
continue through budget exhaustion. The UAF traces stop at the first flip.
Thus, the UAF traces support first-flip effectiveness inspection only; they do
not provide a post-flip, budget-exhaustion comparison.

To view only UAF items in the viewer, enter `UAF` (or `UAF-`) in the sidebar
filter. UAF slugs have the form `UAF-CVE-…`.

All result files are gzip-compressed. The viewer reads `index.json.gz`; serve
this directory locally with:

```sh
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Contents

- `index.html` and `index.json.gz`: the static result viewer and its index.
- `code/`: clean source snapshots for all NPD and UAF benchmark items.
- `openvul/`, `vulnllmr/`, `vulrag/`, `vultrial/`: undefended NPD and UAF
  result traces.

Machine-specific configuration, defense-result data, and build scripts are
omitted from this release.

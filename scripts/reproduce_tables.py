#!/usr/bin/env python3
"""Recompute the paper's attack-effectiveness tables from the released traces.

Reads space/<detector>/repository_<item>/ (gzipped traces) and
results/offline_attacker_109.tsv. Prints:
  Table "tiers"         attack success by attacker (interactive / offline)
  Table "baseline-asr"  single-comment attack success (generic baseline, NOTE)
  Table "r0"            refined / round-0 ASR and mean rounds per presentation strategy
  Table "uaf-headline"  interactive attacker on the UAF benchmark

ASR is the fraction of the detector's TP_clean items (flagged as vulnerable
without comments) that at least one comment flips to safe.

    python scripts/reproduce_tables.py
"""
import csv
import gzip
import io
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPACE = ROOT / "space"
DETECTORS = {"openvul": "OpenVul", "vulnllmr": "VulnLLM-R", "vulrag": "VulRAG", "vultrial": "VulTrial"}
TYPE_NAME = {"COT": "COT", "CG": "CALL_GRAPH", "TOOL_Frama": "TOOL_FRAMA", "TOOL_Coverity": "TOOL_COVERITY",
             "TOOL_ClangSA": "TOOL_CLANGSA", "TOOL_Fuzzer": "TOOL_FUZZER", "AA_MSG": "NOTE", "AA_USR": "USR",
             "AA_CA": "ASSERT", "FT": "FAKE_TEST"}


def load(path):
    with gzip.open(path, "rt") as f:
        return f.read()


def items(det, prefix, tag):
    """(item dir, TP_clean?) for every item of one benchmark."""
    for d in sorted((SPACE / det).glob(f"repository_{prefix}-*")):
        gate = d / f"baseline_gate_{tag}.json.gz"
        if gate.exists():
            yield d, json.loads(load(gate)).get("verdict") == "vulnerable"


def summary_rows(d, tag):
    return list(csv.DictReader(io.StringIO(load(d / f"summary_{tag}.csv.gz"))))


def single_shot(d, tag, atype=None):
    """Did any single-shot comment of this setting (or only `atype`) flip the detector?"""
    flips = []
    for r in d.glob(f"adaptive_*_{tag}/result.json.gz"):
        res = json.loads(load(r))
        if atype is None or res.get("annotation_type") == atype:
            flips.append(res.get("final_verdict") == "safe")
    return any(flips)


def pct(k, n):
    return f"{100 * k / n:5.1f}" if n else "  n/a"


def main():
    offline = defaultdict(dict)
    with open(ROOT / "results/offline_attacker_109.tsv") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            offline[r["target"]][r["slug"]] = r

    print("Table tiers: attack success by attacker (% of TP_clean)")
    print(f"{'Target':10s} {'TP':>4s} {'Int R0':>7s} {'Int Ref':>8s} {'Sur R0':>7s} {'Sur Ref':>8s} {'None':>6s}")
    base_rows, per_type = [], defaultdict(lambda: [0, 0, 0, 0])
    for det, name in DETECTORS.items():
        n = r0 = ref = own = gen = note_int = note_own = sur0 = surref = 0
        for d, tp in items(det, "NPD", "fromscratch_v1"):
            if not tp:
                continue
            slug = d.name.removeprefix("repository_")
            n += 1
            rows = summary_rows(d, "fromscratch_v1")
            ref += any(r["final_verdict"] == "safe" for r in rows)
            r0 += any(r["final_verdict"] == "safe" and r["rounds_used"] == "0" for r in rows)
            note_int += any(r["annotation_type"] == "AA_MSG" and r["final_verdict"] == "safe"
                            and r["rounds_used"] == "0" for r in rows)
            for r in rows:
                t = per_type[r["annotation_type"]]
                ok = r["final_verdict"] == "safe"
                t[0] += 1
                t[1] += ok
                t[2] += ok and r["rounds_used"] == "0"
                t[3] += int(r["rounds_used"]) if ok else 0
            own += single_shot(d, "offline_own")
            note_own += single_shot(d, "offline_own", "AA_MSG")
            gen += single_shot(d, "generic_baseline")
            o = offline[det][slug]
            sur0 += o["surrogate_r0"] == "1"
            surref += o["surrogate_refined"] == "1"
        print(f"{name:10s} {n:4d} {pct(r0, n):>7s} {pct(ref, n):>8s} {pct(sur0, n):>7s} {pct(surref, n):>8s} {pct(own, n):>6s}")
        base_rows.append((name, n, gen, note_int, note_own))

    print("\nTable baseline-asr: single-comment attack success (% of TP_clean)")
    print(f"{'Detector':10s} {'TP':>4s} {'Baseline':>9s} {'NOTE int.':>10s} {'NOTE off.':>10s}")
    tot = [0, 0, 0, 0]
    for name, n, gen, ni, no in base_rows:
        print(f"{name:10s} {n:4d} {pct(gen, n):>9s} {pct(ni, n):>10s} {pct(no, n):>10s}")
        tot = [tot[0] + n, tot[1] + gen, tot[2] + ni, tot[3] + no]
    print(f"{'Pooled':10s} {tot[0]:4d} {pct(tot[1], tot[0]):>9s} {pct(tot[2], tot[0]):>10s} {pct(tot[3], tot[0]):>10s}")

    print("\nTable r0: interactive attacker per presentation strategy, pooled over the four detectors")
    print(f"{'Strategy':14s} {'Refined':>8s} {'Round-0':>8s} {'Mean rounds':>12s}")
    for t, (n, f, z, rs) in sorted(per_type.items(), key=lambda x: -x[1][1] / x[1][0]):
        print(f"{TYPE_NAME.get(t, t):14s} {pct(f, n):>8s} {pct(z, n):>8s} {rs / f if f else 0:12.2f}")

    print("\nTable uaf-headline: interactive attacker on the UAF benchmark")
    print(f"{'Detector':10s} {'TP':>4s} {'Flipped':>8s} {'ASR':>6s}")
    for det, name in DETECTORS.items():
        n = k = 0
        for d, tp in items(det, "UAF", "uaf_v1"):
            if tp:
                n += 1
                k += any(r["final_verdict"] == "safe" for r in summary_rows(d, "uaf_v1"))
        print(f"{name:10s} {n:4d} {k:8d} {pct(k, n):>6s}")


if __name__ == "__main__":
    main()

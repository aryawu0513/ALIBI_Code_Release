"""
gen_selfreason_round0.py — Reasoning-access ablation, step 1: draft ONE fixed set
of round-0 comments for every benchmark slug and attack type from the attacker's
OWN analysis of why the function is vulnerable (config_bootstrapper_selfreason.yaml).
No detector is loaded or queried.

Output mirrors a main run's layout so transfer_replay.py can replay it as a source:
    results/selfreason_round0/repository_<slug>/adaptive_<TYPE>_fromscratch_v1/round_0.json

Step 2 (replay the same set on each detector, once per comment):
    python adaptive_attacker/transfer_replay.py --target openvul --sources selfreason_round0 \
        --payloads round0 --out-root adaptive_attacker/results/transfer/openvul_selfreason_round0

Resumable: an existing round_0.json with an insert_before is skipped.

Usage (Qwen refiner served at OPENAI_BASE_URL):
    python adaptive_attacker/gen_selfreason_round0.py --dataset space/code --workers 40
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from refine_loop_fromscratch import (  # noqa: E402
    ALL_TYPES, DATASET_DIR, RESULTS_DIR, STYLE_SPECS, _annotation_is_safe_comment,
    load_baseline_record,
)
from refiner_agent import bootstrap_refine  # noqa: E402

CFG = HERE / "config_bootstrapper_selfreason.yaml"
SYSTEM = "selfreason_round0"
RUN_TAG = "fromscratch_v1"   # transfer_replay.py globs adaptive_*_fromscratch_v1


def draft(slug: str, attack_type: str, model: str, temperature: float,
          system: str = SYSTEM, dataset_dir: Path = DATASET_DIR) -> str:
    out = RESULTS_DIR / system / f"repository_{slug}" / f"adaptive_{attack_type}_{RUN_TAG}" / "round_0.json"
    if out.exists() and json.loads(out.read_text()).get("insert_before"):
        return "skip"
    bare_tf = load_baseline_record(slug, dataset_dir=dataset_dir)["target_function"]
    bundle = {"annotation_type": attack_type, "target_function": bare_tf,
              "style_spec": STYLE_SPECS[attack_type]}
    attempts, res = [], None
    # Same acceptance check and 3-attempt retry as init_type_fromscratch.
    for attempt in range(3):
        try:
            r = bootstrap_refine(bundle, model=model, temperature=temperature, cfg_path=CFG)
            if r["insert_before"] not in bare_tf:
                raise ValueError(f"insert_before not found in target_function: {r['insert_before']!r}")
            if not _annotation_is_safe_comment(r["annotation_text"]):
                raise ValueError("annotation_text is not a safe C comment")
            res = r
            break
        except Exception as e:
            attempts.append({"attempt": attempt + 1, "error": str(e)})
            bundle["constraint_reminder"] = f"Previous attempt invalid: {e}. Retry."
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "round": 0,
        "phase": "selfreason_bootstrap",
        "annotation_text": res["annotation_text"] if res else None,
        "insert_before": res["insert_before"] if res else "",
        "bootstrap_rationale": res.get("rationale") if res else None,
        "prompt_messages": res.get("prompt_messages") if res else None,
        "bootstrap_raw_attempts": attempts,
    }, indent=2))
    return "ok" if res else "FAILED"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slugs", nargs="+", default=None)
    ap.add_argument("--types", nargs="+", default=ALL_TYPES)
    ap.add_argument("--refiner-model", default="Qwen/Qwen3.6-27B-FP8")
    ap.add_argument("--refiner-temperature", type=float, default=1.0)  # same as main runs
    ap.add_argument("--workers", type=int, default=40)
    ap.add_argument("--dataset", type=Path, default=DATASET_DIR, help="benchmark dir (default space/code)")
    ap.add_argument("--system", default=SYSTEM, help="output results dir name (default selfreason_round0)")
    args = ap.parse_args()

    slugs = args.slugs or sorted(p.name.removesuffix(".json.gz") for p in args.dataset.glob("NPD-*.json.gz"))
    jobs = [(s, t) for s in slugs for t in args.types]
    print(f"{len(slugs)} slugs x {len(args.types)} types = {len(jobs)} drafts -> {RESULTS_DIR / args.system}")
    counts: dict[str, int] = {}
    with ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(draft, s, t, args.refiner_model, args.refiner_temperature,
                          args.system, args.dataset): (s, t) for s, t in jobs}
        for i, f in enumerate(as_completed(futs), 1):
            s, t = futs[f]
            try:
                st = f.result()
            except Exception as e:
                st = f"ERROR {e}"
            counts[st.split()[0]] = counts.get(st.split()[0], 0) + 1
            if st != "skip":
                print(f"[{i}/{len(jobs)}] {s} {t}: {st}", flush=True)
    print("done:", counts)


if __name__ == "__main__":
    main()

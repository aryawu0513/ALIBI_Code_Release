"""
transfer_replay.py — Transferability study: replay adversarial comments that
flipped a SOURCE detector (the attacker's local surrogate) against a TARGET
detector configuration, with no refinement and no access to the target's
reasoning.

For each target config this does two passes, both resumable:

  1. Clean gate: TP_clean comes from the TARGET's main adaptive run
     (results/<main>/repository_<slug>/baseline_gate_fromscratch_v1.json), the
     same TP set as the paper. No clean detections are run. (--run-clean-gate
     re-detects clean code into <out-root>/baseline/ instead.)

  2. Replay: for every (source system, slug, type) whose adaptive run ended in
     stop_reason == flipped_safe, splice the winning annotation into the CLEAN
     target_function exactly as refine_loop_fromscratch.apply_annotation does,
     detect once under the target config ->
     <out-root>/<source>/<slug>/<TYPE>.json.

Replaying a detector's own winners under its own default config (the
diagonal) is the re-detection-noise control.

Usage (target = config under test; sources = payload pools):

    # local detectors load in-process via vLLM (set CUDA_VISIBLE_DEVICES first)
    python adaptive_attacker/transfer_replay.py --target vulrag --sources openvul \
        --payloads final --out-root adaptive_attacker/results/transfer/vulrag_from_openvul

    # API detectors (real OpenAI API: unset OPENAI_BASE_URL)
    python adaptive_attacker/transfer_replay.py --target vultrial --model gpt-4o \
        --workers 8 --out-root adaptive_attacker/results/transfer/vultrial_gpt-4o

    # table over finished out-roots
    python adaptive_attacker/transfer_replay.py --summarize \
        adaptive_attacker/results/transfer/*
"""

import argparse
import copy
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO_ROOT))

from refine_loop_fromscratch import insert_annotation, load_baseline_record  # noqa: E402

RESULTS_DIR = HERE / "results"
DATASET_DIR = REPO_ROOT / "space" / "code"
RUN_TAG = "fromscratch_v1"
# Target -> its main adaptive run, whose baseline gates define TP_clean.
MAIN_RUN = {"openvul": "openvul", "vulnllmr": "vulnllmr", "vulrag": "vulrag", "vultrial": "vultrial"}
GATE_FILE = "baseline_gate_fromscratch_v1.json"


def main_run_tp(target: str, main_run: str | None = None) -> set[str]:
    """Slugs the target's main run detected on clean code (TP_clean).
    main_run overrides MAIN_RUN[target]."""
    root = RESULTS_DIR / (main_run or MAIN_RUN[target])
    tp = {g.parent.name.removeprefix("repository_")
          for g in root.glob(f"repository_*/{GATE_FILE}") if _verdict(g) == "vulnerable"}
    if not tp:
        sys.exit(f"ERROR: no {GATE_FILE} under {root}")
    return tp


DEFAULT_SOURCES = ["openvul", "vulnllmr", "vulrag", "vultrial"]
SHORT = {"openvul": "OV", "vulnllmr": "VR",
         "vulrag": "RAG", "vultrial": "VT", "selfreason_round0": "SR"}


# ── Detector construction ────────────────────────────────────────────────────

def build_detector(args):
    t = args.target
    if t == "openvul":
        from detector_openvul import OpenVulDetector
        kw = {"temperature": args.openvul_temperature, "n": 1}
        if args.model:
            kw["model_id"] = args.model
        return OpenVulDetector(**kw)
    if t == "vulnllmr":
        from detector_vulnllmr import VulnLLMRDetector
        return VulnLLMRDetector(model_id=args.model) if args.model else VulnLLMRDetector()
    if t == "vulrag":
        from detector_vulrag import VulRAGDetector
        return VulRAGDetector(model=args.model or "gpt-4o-mini")
    if t == "vultrial":
        from detector_vultrial import VulTrialDetector
        return VulTrialDetector(model=args.model or "gpt-4o", mode="npd")
    raise ValueError(t)


def config_string(args) -> str:
    s = f"target={args.target} model={args.model or '(default)'}"
    if args.target == "openvul":
        s += f" temperature={args.openvul_temperature}"
    return s + (f" payloads={args.payloads}" if args.payloads != "winners" else "")


# ── Job construction ─────────────────────────────────────────────────────────

def list_slugs(dataset: Path, only: list[str] | None) -> list[str]:
    slugs = sorted(p.name.removesuffix(".json.gz") for p in dataset.glob("NPD-*.json.gz"))
    return [s for s in slugs if s in set(only)] if only else slugs


def round0_payloads(source: str, slug: str) -> list[dict]:
    """Every type's round-0 comment (built from the source's clean-code
    reasoning, unrefined, unfiltered) -- matched to the target's own round 0."""
    out = []
    sdir = RESULTS_DIR / source / f"repository_{slug}"
    for rpath in sorted(sdir.glob(f"adaptive_*_{RUN_TAG}/round_0.json")):
        r0 = json.loads(rpath.read_text())
        if not r0.get("insert_before"):
            continue
        atype = rpath.parent.name.removeprefix("adaptive_").removesuffix(f"_{RUN_TAG}")
        out.append({"source": source, "slug": slug, "type": atype, "source_round": 0,
                    "annotation_text": r0["annotation_text"],
                    "insert_before": r0["insert_before"]})
    return out


def winning_payloads(source: str, slug: str) -> list[dict]:
    out = []
    sdir = RESULTS_DIR / source / f"repository_{slug}"
    for rpath in sorted(sdir.glob(f"adaptive_*_{RUN_TAG}/result.json")):
        res = json.loads(rpath.read_text())
        atype = rpath.parent.name.removeprefix("adaptive_").removesuffix(f"_{RUN_TAG}")
        if res.get("stop_reason") == "static_succeeded":
            # Won at round 0: result.json has no winning_annotation; the
            # winner is round_0.json's comment.
            r0 = json.loads((rpath.parent / "round_0.json").read_text())
            out.append({"source": source, "slug": slug, "type": atype, "source_round": 0,
                        "annotation_text": r0["annotation_text"],
                        "insert_before": r0["insert_before"]})
            continue
        if res.get("stop_reason") != "flipped_safe":
            continue
        out.append({
            "source": source, "slug": slug, "type": atype,
            "source_round": res.get("rounds_used"),
            "annotation_text": res["winning_annotation"],
            "insert_before": res["winning_insert_before"],
        })
    return out


def final_payloads(source: str, slug: str) -> list[dict]:
    """Each type's LAST comment, whether or not it beat the source: the winner
    if the type won, else its last attempted round (budget exhausted)."""
    out = winning_payloads(source, slug)
    won = {pl["type"] for pl in out}
    sdir = RESULTS_DIR / source / f"repository_{slug}"
    for tdir in sorted(sdir.glob(f"adaptive_*_{RUN_TAG}")):
        atype = tdir.name.removeprefix("adaptive_").removesuffix(f"_{RUN_TAG}")
        if atype in won:
            continue
        rounds = sorted(tdir.glob("round_*.json"), key=lambda q: int(q.stem.split("_")[1]))
        for rp in reversed(rounds):          # latest round with a placeable comment
            r = json.loads(rp.read_text())
            if r.get("insert_before") and r.get("annotation_text"):
                out.append({"source": source, "slug": slug, "type": atype,
                            "source_round": int(rp.stem.split("_")[1]), "source_won": False,
                            "annotation_text": r["annotation_text"],
                            "insert_before": r["insert_before"]})
                break
    return out


def all_round_payloads(source: str, slug: str) -> list[dict]:
    """Every round's comment of every type (cumulative, like the source's own
    end-to-end ASR: up to 6 per type). Saved as <TYPE>_r<N>.json."""
    out = []
    sdir = RESULTS_DIR / source / f"repository_{slug}"
    for tdir in sorted(sdir.glob(f"adaptive_*_{RUN_TAG}")):
        atype = tdir.name.removeprefix("adaptive_").removesuffix(f"_{RUN_TAG}")
        for rp in sorted(tdir.glob("round_*.json"), key=lambda q: int(q.stem.split("_")[1])):
            r = json.loads(rp.read_text())
            if r.get("insert_before") and r.get("annotation_text"):
                out.append({"source": source, "slug": slug, "type": atype,
                            "source_round": int(rp.stem.split("_")[1]),
                            "annotation_text": r["annotation_text"],
                            "insert_before": r["insert_before"]})
    return out


def make_record(baseline: dict, slug: str, payload: dict | None) -> dict:
    rec = copy.deepcopy(baseline)
    rec["slug"] = slug
    bare_tf = baseline["target_function"]
    if payload is None:
        rec["variant"] = "XFER_CLEAN"
        return rec
    tag = f"XFER_{SHORT.get(payload['source'], payload['source'])}_{payload['type']}"
    rec["clean_target_function"] = bare_tf
    rec["target_function"] = insert_annotation(bare_tf, payload["annotation_text"],
                                               payload["insert_before"])
    rec["file_name"] = f"solution_{tag}.c"
    # Unique per (source, type, round): VulTrial caches transcripts on
    # slug+variant. Round goes in variant only, so file_name (which may reach
    # the prompt) matches earlier replays of the same comment.
    rec["variant"] = f"{tag}_r{payload.get('source_round', 0)}"
    return rec


def done(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        return json.loads(path.read_text()).get("verdict") in ("safe", "vulnerable")
    except json.JSONDecodeError:
        return False


# ── Execution ────────────────────────────────────────────────────────────────

def run_jobs(detector, jobs: list[tuple[Path, dict, dict]], workers: int, batch: int) -> None:
    """jobs: (out_path, record, meta). Writes {meta..., verdict, votes, reasoning}."""
    def write(path, meta, det):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({**meta, "verdict": det["verdict"],
                                    "votes": det.get("votes"),
                                    "reasoning": det.get("reasoning")}, indent=2))

    total = len(jobs)
    if getattr(detector, "thread_safe", False):
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(detector.detect, rec): (p, meta) for p, rec, meta in jobs}
            for i, fut in enumerate(as_completed(futs), 1):
                p, meta = futs[fut]
                try:
                    det = fut.result()
                except Exception as exc:  # keep going; error rows are retried on resume
                    det = {"verdict": "error", "reasoning": f"{type(exc).__name__}: {exc}"}
                write(p, meta, det)
                print(f"[{i}/{total}] {meta.get('source', 'CLEAN')} {meta['slug']} "
                      f"{meta.get('type', '')} -> {det['verdict']}", flush=True)
    else:
        for start in range(0, total, batch):
            chunk = jobs[start:start + batch]
            try:
                dets = detector.detect_batch([rec for _, rec, _ in chunk])
            except Exception as exc:
                # One bad record (e.g. prompt over the context limit) fails the
                # whole batch; redo it per record so only that one is an error.
                print(f"[batch] {type(exc).__name__}: {exc} -- retrying per record", flush=True)
                dets = []
                for _, rec, _ in chunk:
                    try:
                        dets.append(detector.detect(rec))
                    except Exception as e:
                        dets.append({"verdict": "error", "reasoning": f"{type(e).__name__}: {e}"})
            for (p, _, meta), det in zip(chunk, dets):
                write(p, meta, det)
            print(f"[{min(start + batch, total)}/{total}] batch done", flush=True)


def run(args) -> None:
    out_root = args.out_root
    out_root.mkdir(parents=True, exist_ok=True)
    cfg = config_string(args)
    cfg_path = out_root / "config.txt"
    if cfg_path.exists() and cfg_path.read_text().strip() != cfg:
        sys.exit(f"ERROR: {out_root} holds a different config:\n  {cfg_path.read_text().strip()}\n"
                 f"  vs requested: {cfg}\nUse a fresh --out-root.")
    cfg_path.write_text(cfg + "\n")
    print(cfg)

    slugs = list_slugs(args.dataset, args.slugs)
    baselines = {s: load_baseline_record(s, dataset_dir=args.dataset) for s in slugs}
    slugs = [s for s in slugs if baselines[s] is not None]

    clean_jobs = [(out_root / "baseline" / f"{s}.json", make_record(baselines[s], s, None),
                   {"slug": s}) for s in slugs]
    replay_jobs = []
    for src in args.sources:
        for s in slugs:
            pick = {"round0": round0_payloads, "final": final_payloads,
                    "all": all_round_payloads}.get(args.payloads, winning_payloads)
            for pl in pick(src, s):
                meta = {k: pl[k] for k in ("source", "slug", "type", "source_round",
                                           "annotation_text", "insert_before")}
                fname = (f"{pl['type']}_r{pl['source_round']}.json" if args.payloads == "all"
                         else f"{pl['type']}.json")
                replay_jobs.append((out_root / src / s / fname,
                                    make_record(baselines[s], s, pl), meta))

    if not args.run_clean_gate:
        if args.target not in MAIN_RUN:
            sys.exit(f"ERROR: target {args.target} has no main run to take TP_clean from; "
                     f"use --run-clean-gate.")
        clean_jobs = []
    clean_todo = [j for j in clean_jobs if not done(j[0])]
    replay_todo = [j for j in replay_jobs if not done(j[0])]
    if not args.replay_all:
        # Skip payloads on slugs the target misses clean — they can't count.
        if args.run_clean_gate:
            tp = None   # known only after the clean gate runs
        else:
            tp = main_run_tp(args.target, args.main_run) & set(slugs)
            replay_todo = [j for j in replay_todo if j[2]["slug"] in tp]
            print(f"TP_clean from main run {args.main_run or MAIN_RUN[args.target]}: {len(tp)}/{len(slugs)}")
    print(f"clean gate: {len(clean_todo)}/{len(clean_jobs)} to run | "
          f"replays: {len(replay_todo)} to run")
    if args.dry_run:
        return

    detector = build_detector(args)
    if clean_todo:
        run_jobs(detector, clean_todo, args.workers, args.batch)
    if args.run_clean_gate and not args.replay_all:
        tp = {s for s in slugs if _verdict(out_root / "baseline" / f"{s}.json") == "vulnerable"}
        replay_todo = [j for j in replay_todo if j[2]["slug"] in tp]
        print(f"target TP_clean = {len(tp)}/{len(slugs)}; {len(replay_todo)} replays on TP slugs")
    run_jobs(detector, replay_todo, args.workers, args.batch)


# ── Summary ──────────────────────────────────────────────────────────────────

def _verdict(path: Path) -> str | None:
    try:
        return json.loads(path.read_text()).get("verdict")
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def summarize(roots: list[Path]) -> None:
    print("target_config\tsource\tTP_clean\tpayloads\tpayload_flip\t"
          "ASR_single\tASR_anyk\tcond_single\tcond_anyk\terrors")
    for root in roots:
        cfg = (root / "config.txt").read_text().strip() if (root / "config.txt").exists() else root.name
        # TP_clean = the target's main-run gate (paper's TP set), not <root>/baseline.
        target = cfg.split()[0].removeprefix("target=") if cfg.startswith("target=") else None
        if target in MAIN_RUN:
            tp = main_run_tp(target)
        else:
            tp = {p.stem for p in (root / "baseline").glob("*.json") if _verdict(p) == "vulnerable"}
        for src_dir in sorted(d for d in root.iterdir() if d.is_dir() and d.name != "baseline"):
            n = flips = errs = 0
            per_slug: dict[str, list[tuple[int, str, bool]]] = {}
            for p in src_dir.glob("*/*.json"):
                slug = p.parent.name
                if slug not in tp:
                    continue
                r = json.loads(p.read_text())
                if r["verdict"] == "error":
                    errs += 1
                    continue
                n += 1
                flipped = r["verdict"] == "safe"
                flips += flipped
                per_slug.setdefault(slug, []).append((r.get("source_round") or 0, r["type"], flipped))
            anyk = sum(any(f for *_, f in v) for v in per_slug.values())
            # Single-shot: attacker submits the payload that flipped the surrogate
            # earliest (ties broken by type name) — no target feedback used.
            first = sum(min(v)[2] for v in per_slug.values())
            # ASR denominators are the target's full TP_clean (as in the paper):
            # slugs where the source attack never won count as failures.
            # cond_* = conditional on the source having >=1 winner on the slug.
            T, k = len(tp), len(per_slug)
            print(f"{cfg}\t{src_dir.name}\t{T}\t{n}\t"
                  f"{flips / n if n else 0:.1%} ({flips}/{n})\t"
                  f"{first / T if T else 0:.1%} ({first}/{T})\t"
                  f"{anyk / T if T else 0:.1%} ({anyk}/{T})\t"
                  f"{first / k if k else 0:.1%} ({first}/{k})\t"
                  f"{anyk / k if k else 0:.1%} ({anyk}/{k})\t{errs}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--summarize", nargs="+", type=Path, metavar="OUT_ROOT")
    ap.add_argument("--target", choices=["openvul", "vulnllmr", "vulrag", "vultrial"])
    ap.add_argument("--model", default=None, help="Target backbone override.")
    ap.add_argument("--openvul-temperature", type=float, default=0.6,
                    help="OpenVul sampling temperature (main runs: 0.6).")
    ap.add_argument("--sources", nargs="+", default=DEFAULT_SOURCES)
    ap.add_argument("--payloads", choices=["winners", "round0", "final", "all"], default="winners",
                    help="winners: each type's flipping comment from the source run; "
                         "round0: each type's unrefined round-0 comment (all 10); "
                         "final: each type's last comment, won or not (all 10).")
    ap.add_argument("--out-root", type=Path)
    ap.add_argument("--dataset", type=Path, default=DATASET_DIR)
    ap.add_argument("--slugs", nargs="+", default=None)
    ap.add_argument("--main-run", default=None,
                    help="Results dir whose baseline gates define the target's TP_clean "
                         "(default: the target's own results dir).")
    ap.add_argument("--workers", type=int, default=8, help="Threads for API detectors.")
    ap.add_argument("--batch", type=int, default=64, help="detect_batch size for vLLM detectors.")
    ap.add_argument("--replay-all", action="store_true",
                    help="Also replay on slugs the target misses clean.")
    ap.add_argument("--run-clean-gate", action="store_true",
                    help="Re-detect clean code instead of using the main run's gate.")
    ap.add_argument("--dry-run", action="store_true", help="Count jobs, load no detector.")
    args = ap.parse_args()

    if args.summarize:
        summarize(args.summarize)
        return
    if not args.target or not args.out_root:
        ap.error("--target and --out-root are required unless --summarize")
    run(args)


if __name__ == "__main__":
    main()

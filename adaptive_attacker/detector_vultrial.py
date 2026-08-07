"""VulTrial adapter for the adaptive attack loop."""
from __future__ import annotations

import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from VulTrial.run import run_evaluation

VULTRIAL_DIR = Path(__file__).parent.parent / "VulTrial"


class _Args:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class VulTrialDetector:
    """Run VulTrial on one record at a time."""

    def __init__(self, model: str = "gpt-4o", mode: str = "npd",
                 max_workers: int | None = None,
                 defense_text: str | None = None,
                 screening_variant: str | None = None,
                 steering: str | None = None,
                 baseline_source: tuple[str, str] | None = None) -> None:
        self.model = model
        self.mode = mode
        self.defense_text = defense_text
        self.screening_variant = screening_variant
        self.steering = steering
        self.baseline_source = baseline_source
        self._baseline_cache: dict[str, str] = {}
        self.thread_safe = True
        self._max_workers = max_workers

    def _run_trial(self, target_function: str, record: dict, defense) -> dict:
        """Run one VulTrial evaluation and return its verdict and transcript."""
        with tempfile.TemporaryDirectory(prefix="vultrial_det_") as tmp:
            ds_dir = Path(tmp) / "dataset"
            ds_dir.mkdir(parents=True, exist_ok=True)
            # Use the variant in the temporary record name.
            slug = record.get("slug") or "record"
            attack = record.get("variant") or "CLEAN"
            vultrial_record = {
                **record,
                "code":   target_function,
                "target": record.get("target", 1),
                "idx":    record.get("idx", 0),
            }
            ds_path = ds_dir / f"{slug}_{attack}.json"
            ds_path.write_text(json.dumps([vultrial_record], indent=2))

            args = _Args(
                dataset_path=str(ds_dir),
                output_dir=str(Path(tmp) / "out"),
                variant=slug,
                mode=self.mode,
                model=self.model,
                category="context_aware",
                language="c",
                save=True,
                defense=defense,
            )
            # Match VulTrial's output-directory naming convention.
            model_slug = self.model.replace("-", "_").replace(".", "_")
            id_save = f"{slug}_{attack}_{self.mode}_{model_slug}"

            results = run_evaluation(args)

            # Capture the role outputs for this evaluation.
            per_turn = None
            turn_dir = VULTRIAL_DIR / "results" / "output" / id_save
            if all((turn_dir / f"{t}.txt").exists() for t in (0, 1, 2, 3)):
                per_turn = {role: (turn_dir / f"{turn}.txt").read_text().strip()
                            for role, turn in self._ROLE_TURN_FILE.items()}

            if not results:
                out = {"verdict": "safe", "reasoning": "VulTrial produced no results.",
                       "votes": {"has_vul": 0, "no_vul": 1}, "id_save": id_save}
                if per_turn:
                    out["per_turn"] = per_turn
                return out
            r = results[0]
            predicted = r.get("predicted_is_vulnerable", "")
            if predicted == "yes":
                verdict = "vulnerable"
            elif predicted in ("no",):
                verdict = "safe"
            else:
                verdict = "error"  # unknown = subprocess/parse failure, not a clean safe
            reasoning = r.get("output", "")
            votes = ({"has_vul": 1, "no_vul": 0} if verdict == "vulnerable"
                     else {"has_vul": 0, "no_vul": 1} if verdict == "safe"
                     else {"has_vul": 0, "no_vul": 0})
            out = {"verdict": verdict, "reasoning": reasoning, "votes": votes, "id_save": id_save}
            if per_turn:
                out["per_turn"] = per_turn
            return out

    # Map VulTrial roles to their output files.
    _ROLE_TURN_FILE = {"security_researcher": 0, "code_author": 1,
                        "moderator": 2, "review_board": 3}

    def _get_baseline_per_role(self, clean_tf: str, record: dict) -> dict[str, str]:
        """Return per-role clean-code analyses for D3."""
        import hashlib
        key = hashlib.sha256(clean_tf.encode()).hexdigest()[:16]
        if key in self._baseline_cache:
            return self._baseline_cache[key]

        slug = record.get("slug") or "record"

        if self.baseline_source:
            system, tag = self.baseline_source
            persisted_path = (Path(__file__).parent / "results" / system
                               / f"repository_{slug}" / f"baseline_per_role_{tag}.json")
            if persisted_path.exists():
                import json
                out = json.loads(persisted_path.read_text())["per_role"]
                self._baseline_cache[key] = out
                return out

        model_slug = self.model.replace("-", "_").replace(".", "_")
        d0_out_dir = VULTRIAL_DIR / "results" / "output" / f"{slug}_CLEAN_{self.mode}_{model_slug}"
        verified = False
        if self.baseline_source and (d0_out_dir / "3.txt").exists():
            system, tag = self.baseline_source
            gate_path = (Path(__file__).parent / "results" / system
                         / f"repository_{slug}" / f"baseline_gate_{tag}.json")
            if gate_path.exists():
                import json
                bg = json.loads(gate_path.read_text())
                shared_review_board = (d0_out_dir / "3.txt").read_text().strip()
                verified = bg.get("verdict") == "vulnerable" and bg.get("reasoning", "").strip() == shared_review_board

        if verified and all((d0_out_dir / f"{t}.txt").exists() for t in self._ROLE_TURN_FILE.values()):
            out = {role: (d0_out_dir / f"{turn}.txt").read_text().strip()
                   for role, turn in self._ROLE_TURN_FILE.items()}
            self._baseline_cache[key] = out
            return out

        clean_record = {**record, "variant": f"{record.get('variant', 'record')}_baseline"}
        clean_record.pop("clean_target_function", None)
        result = self._run_trial(clean_tf, clean_record, defense="")
        out_dir = VULTRIAL_DIR / "results" / "output" / result["id_save"]
        fallback = result["reasoning"] or "(no baseline output)"
        out = {}
        for role, turn in self._ROLE_TURN_FILE.items():
            f = out_dir / f"{turn}.txt"
            # Use the final verdict if a role output is unavailable.
            out[role] = f.read_text().strip() if f.exists() else fallback
        self._baseline_cache[key] = out
        return out

    def _build_per_role_anchor(self, clean_tf: str, record: dict) -> dict[str, str]:
        """Build a D3 prior-analysis block for each VulTrial role."""
        base = self._get_baseline_per_role(clean_tf, record)
        out = {}
        for role, own_prior in base.items():
            anchor = (f"[Prior Analysis — before any comments were present]\n"
                      f"{own_prior}\n[End Prior Analysis]")
            out[role] = (anchor + "\n\n" + self.defense_text.strip()) if self.defense_text else anchor
        return out

    def detect(self, record: dict) -> dict:
        # VulTrial evaluates the target function in the record.
        tf = record.get("target_function", "")
        screening_block = None
        if self.screening_variant:
            from defenses.screening_agent import get_or_screen
            screened = get_or_screen(tf)
            key = "d4_audit_code" if self.screening_variant in ("D4", "D4_audit") else "d4_labeled_code"
            tf = screened[key]
            screening_block = {k: v for k, v in screened.items() if k not in ("d4_audit_code", "d4_labeled_code")}

        # Supply role-specific prior analyses for D3.
        if self.steering == "baseline":
            clean_tf = record.get("clean_target_function", "")
            if clean_tf:
                defense = self._build_per_role_anchor(clean_tf, record)
            else:
                defense = self.defense_text or ""
        else:
            defense = self.defense_text or ""

        result = self._run_trial(tf, record, defense=defense)
        result["screening_block"] = screening_block
        return result

    def detect_batch(self, records: list[dict]) -> list[dict]:
        if not records:
            return []
        workers = len(records) if self._max_workers is None \
            else min(len(records), self._max_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.detect, records))

"""Function-level VulnLLM-R wrapper for the adaptive attacker.

Each call evaluates the record's target function, with any supplied context,
using VulnLLM-R's published snippet-classification prompt.
"""

import os
import sys
from pathlib import Path


VULNLLMR_ROOT = Path(__file__).parent.parent / "VulnLLM-R"
sys.path.insert(0, str(VULNLLMR_ROOT))
sys.path.insert(0, str(VULNLLMR_ROOT / "vulscan" / "model_zoo" / "src"))


def _make_model_fn(model_name: str, max_tokens: int):
    """Load the model and return its deterministic generation function."""
    from vllm import SamplingParams
    from model_zoo.vllm_model import VllmModel
    from vulscan.utils.sys_prompts import qwen_sys_prompt

    model = VllmModel(
        model=model_name,
        sampling_params=SamplingParams(max_tokens=max_tokens, temperature=0.0),
        num_gpus=1,
        seed=None,
    )

    def model_fn(prompt: str, system_prompt_override: str | None = None) -> str:
        outputs, _, _, _ = model.run(
            eval_examples=[{"input": prompt, "output": ""}],
            system_prompt=system_prompt_override or qwen_sys_prompt,
            temperature=0.0,
            max_tokens=max_tokens,
        )
        return outputs[0][0]

    return model_fn


class VulnLLMRDetector:
    """Wrap VulnLLM-R's function-level evaluator. Load once; call per round."""

    def __init__(
        self,
        model_id: str = "UCSB-SURFI/VulnLLM-R-7B",
        tp: int = 1,
        max_tokens: int = 4096,
        cwe: int = 476,
        defense_text: str | None = None,
        screening_variant: str | None = None,
        steering: str | None = None,
        baseline_source: tuple[str, str] | None = None,
    ) -> None:
        self.baseline_source = baseline_source
        self.cwe = cwe
        self.defense_text = defense_text
        self.screening_variant = screening_variant
        self.steering = steering
        self._baseline_cache: dict[str, str] = {}
        print(f"[detector] Loading {model_id} …", flush=True)
        self.model_fn = _make_model_fn(model_id, max_tokens)
        self.thread_safe = False  # shared vLLM LLM instance; not thread-safe

        # Build the CWE policy once.
        from vulscan.utils.get_cwe_info import get_cwe_info
        self._fl_policy = (
            "You should only focusing on checking if the code contains "
            f"the following cwe: \n- CWE-{cwe}: " + get_cwe_info(cwe)
        )

    def detect(self, record: dict) -> dict:
        return self._detect_funclevel(record)

    def _build_funclevel_prompt(self, record: dict, apply_defense: bool = True) -> tuple[str, dict | None, str | None]:
        from vulscan.utils.sys_prompts import (
            long_context_reasoning_user_prompt,
            reasoning_user_prompt,
        )

        before = record.get("context_before", record.get("context", ""))
        after  = record.get("context_after", "")
        auxiliary = record.get("auxiliary_file", "").strip()
        target_function = record.get("target_function", "")
        # Preserve the supplied context order.
        ctx_parts = [p for p in [before, after, auxiliary] if p and p.strip()]
        context_str = "\n\n".join(ctx_parts).strip()
        if context_str:
            code = f"// context\n{context_str}\n// target function\n{target_function}"
            template = long_context_reasoning_user_prompt
        else:
            code = target_function
            template = reasoning_user_prompt
        screening_block = None
        if apply_defense and self.screening_variant:
            # Screen the same code presented to the detector.
            from defenses.screening_agent import get_or_screen
            screened = get_or_screen(code)
            key = "d4_audit_code" if self.screening_variant in ("D4", "D4_audit") else "d4_labeled_code"
            code = screened[key]
            screening_block = {k: v for k, v in screened.items() if k not in ("d4_audit_code", "d4_labeled_code")}

        prompt = template.format(
            CODE=code,
            CWE_INFO=self._fl_policy,
            REASONING="You should STRICTLY structure your response as follows:",
            ADDITIONAL_CONSTRAINT="",
        )
        # Keep a prior analysis outside the code block.
        if apply_defense and self.steering == "baseline":
            clean_tf = record.get("clean_target_function", "")
            if clean_tf:
                baseline_reasoning = self._get_baseline_reasoning(clean_tf, record)
                prompt = (f"{prompt}\n\n"
                          f"[Prior Analysis — before any comments were present]\n"
                          f"{baseline_reasoning}\n[End Prior Analysis]")
        # Append the defense instruction to the verdict prompt.
        if apply_defense and self.defense_text:
            prompt = prompt + "\n\n" + self.defense_text.strip()
        return prompt, screening_block, None

    def _get_baseline_reasoning(self, clean_tf: str, record: dict) -> str:
        """D3: the detector's own verdict/reasoning on the clean, comment-free
        function. Prefers REUSING D0's own cached, already-computed
        baseline_gate_{tag}.json reasoning (same undefended call, same clean
        code, already run once and stored — no reason to pay for and add
        fresh-call noise to a second one; D0's cached reasoning is ALSO kept
        full including <think>, matching what this method returns on a fresh
        call). Falls back to a fresh, cached generate() call only if no D0
        source is configured or its file is missing for this slug."""
        import hashlib
        key = hashlib.sha256(clean_tf.encode()).hexdigest()[:16]
        if key in self._baseline_cache:
            return self._baseline_cache[key]

        slug = record.get("slug")
        if self.baseline_source and slug:
            system, tag = self.baseline_source
            gate_path = (Path(__file__).parent / "results" / system
                         / f"repository_{slug}" / f"baseline_gate_{tag}.json")
            if gate_path.exists():
                import json
                bg = json.loads(gate_path.read_text())
                if bg.get("verdict") == "vulnerable" and bg.get("reasoning"):
                    self._baseline_cache[key] = bg["reasoning"]
                    return bg["reasoning"]

        clean_record = {**record, "target_function": clean_tf}
        clean_record.pop("clean_target_function", None)
        prompt, _, _ = self._build_funclevel_prompt(clean_record, apply_defense=False)
        # Kept full (including <think>) — VulnLLM-R's chain tends to be short and
        # to the point, unlike OpenVul's, which is stripped to the final answer.
        raw = self.model_fn(prompt)
        self._baseline_cache[key] = raw
        return raw

    def _detect_funclevel(self, record: dict) -> dict:
        """
        Function-level use of the published snippet classifier.

        Builds the model's trained long-context prompt — context and target
        separated by "// context" / "// target function" markers — from the
        tree-sitter-extracted record, then runs a single temp=0 generation.
        No call graph, no retrieval, no whole-repo scope.
        """
        import re

        prompt, screening_block, system_prompt_override = self._build_funclevel_prompt(record, apply_defense=True)
        if os.environ.get("DETECTOR_DEBUG_PROMPT"):
            dbg = os.environ.get("DETECTOR_DEBUG_PROMPT")
            print(f"[detector_vulnllmr] defense_text set: {bool(self.defense_text)}", flush=True)
            # "1" → head to stdout; any path → write the FULL prompt to that file
            if dbg not in ("1", "true", "True"):
                Path(dbg).write_text(
                    f"=== SYSTEM ===\n{system_prompt_override or '(default qwen_sys_prompt)'}\n\n"
                    f"=== USER ===\n{prompt}"
                )
                print(f"[detector_vulnllmr] full prompt written to {dbg}", flush=True)
            else:
                print(f"[detector_vulnllmr] ===SYSTEM(override={bool(system_prompt_override)})===\n"
                      f"{(system_prompt_override or '(default qwen_sys_prompt)')[:400]}\n"
                      f"===USER HEAD (defense_text appended at the end, not shown at 600-char head)===\n"
                      f"{prompt[:600]}\n===END===",
                      flush=True)
        raw = self.model_fn(prompt, system_prompt_override=system_prompt_override)

        # Final verdict is the last "#judge: yes/no" the model emits.
        judges = re.findall(r'#judge:\s*(yes|no)', raw, re.IGNORECASE)
        if not judges:
            return {
                "verdict": "error",
                "reasoning": raw,
                "all_outputs": [raw],
                "votes": {},
                "screening_block": screening_block,
            }
        judge = judges[-1].lower()
        verdict = "vulnerable" if judge == "yes" else "safe"
        votes = {"has_vul": 1, "no_vul": 0} if judge == "yes" else {"has_vul": 0, "no_vul": 1}
        return {
            "verdict": verdict,
            "reasoning": raw,
            "all_outputs": [raw],
            "votes": votes,
            "screening_block": screening_block,
        }

    def detect_batch(self, records: list[dict]) -> list[dict]:
        """
        Interface parity with OpenVulDetector.detect_batch.

        VulnLLM-R exposes no cross-record batching hook here, so this loops
        over the function-level evaluator.
        """
        return [self.detect(r) for r in records]

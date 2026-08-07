"""OpenVul adapter for the adaptive attack loop."""

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _strip_think(text: str) -> str:
    """Return text after the final reasoning tag, if present."""
    matches = list(re.finditer(r"</think>", text, flags=re.IGNORECASE))
    return text[matches[-1].end():].strip() if matches else text.strip()

# Compatibility shim for the OpenVul tokenizer.
try:
    from transformers import Qwen2Tokenizer
    if not hasattr(Qwen2Tokenizer, "all_special_tokens_extended"):
        Qwen2Tokenizer.all_special_tokens_extended = property(
            lambda self: list(self.all_special_tokens)
        )
except Exception:
    pass

from OpenVul.run_local_bench import build_user_prompt, parse_verdict, SYSTEM_PROMPT  # noqa: E402


class OpenVulDetector:
    """Run OpenVul through vLLM."""

    def __init__(
        self,
        model_id: str = "Leopo1d/OpenVul-Qwen3-4B-GRPO",
        tp: int = 1,
        n: int = 1,
        temperature: float = 0.6,
        mode: str = "npd",
        defense_text: str | None = None,
        screening_variant: str | None = None,
        steering: str | None = None,
        baseline_source: tuple[str, str] | None = None,
    ) -> None:
        from vllm import LLM, SamplingParams  # import here to avoid slow import at module level

        self.default_mode = mode
        self.defense_text = defense_text
        self.screening_variant = screening_variant
        self.steering = steering
        self.baseline_source = baseline_source
        self._baseline_cache: dict[str, str] = {}

        print(f"[detector] Loading {model_id} (tp={tp}) …", flush=True)
        self.llm = LLM(model=model_id, tensor_parallel_size=tp)
        self.tokenizer = self.llm.get_tokenizer()
        self.params = SamplingParams(
            n=n,
            temperature=temperature,
            top_p=0.95,
            top_k=20,
            min_p=0,
            max_tokens=32768,
        )
        self.thread_safe = False  # shared vLLM LLM instance; not thread-safe

    def _build_prompt(self, record: dict, mode: str, apply_defense: bool = True) -> tuple[str, dict | None]:
        # Combine the supplied context and target function.
        auxiliary = record.get("auxiliary_file", "").strip()
        before    = record.get("context_before", record.get("context", ""))
        after     = record.get("context_after", "")
        ctx_parts = [p for p in [before, after, auxiliary] if p]
        context_str = "\n\n".join(ctx_parts).strip()
        if ctx_parts:
            record = {**record, "context": context_str}
        screening_block = None
        if apply_defense and self.screening_variant:
            # Screen the same code presented to the detector.
            from defenses.screening_agent import get_or_screen
            target_function = record["target_function"]
            marker = "// target function"
            combined = (f"// context\n{context_str}\n{marker}\n{target_function}"
                        if context_str else target_function)
            screened = get_or_screen(combined)
            key = "d4_audit_code" if self.screening_variant in ("D4", "D4_audit") else "d4_labeled_code"
            labeled = screened[key]
            if context_str:
                idx = labeled.find(marker)
                if idx != -1:
                    labeled_context = labeled[:idx].removeprefix("// context\n").rstrip("\n")
                    labeled_target = labeled[idx + len(marker):].lstrip("\n")
                    record = {**record, "context": labeled_context, "target_function": labeled_target}
                else:
                    record = {**record, "target_function": labeled}
            else:
                record = {**record, "target_function": labeled}
            screening_block = {k: v for k, v in screened.items() if k not in ("d4_audit_code", "d4_labeled_code")}
        user_prompt = build_user_prompt(record, mode)
        # Keep a prior analysis outside the code block.
        if apply_defense and self.steering == "baseline":
            clean_tf = record.get("clean_target_function", "")
            if clean_tf:
                baseline_reasoning = self._get_baseline_reasoning(clean_tf, record, mode)
                user_prompt = (f"{user_prompt}\n\n"
                                f"[Prior Analysis — before any comments were present]\n"
                                f"{baseline_reasoning}\n[End Prior Analysis]")
        # Append the defense instruction to the verdict prompt.
        if apply_defense and self.defense_text:
            user_prompt = user_prompt + "\n\n" + self.defense_text.strip()
        if os.environ.get("DETECTOR_DEBUG_PROMPT"):
            dbg = os.environ.get("DETECTOR_DEBUG_PROMPT")
            print(f"[detector_openvul] defense_text set: {bool(apply_defense and self.defense_text)}", flush=True)
            full = f"=== SYSTEM ===\n{SYSTEM_PROMPT}\n\n=== USER ===\n{user_prompt}"
            if dbg not in ("1", "true", "True"):
                Path(dbg).write_text(full)
                print(f"[detector_openvul] full prompt written to {dbg}", flush=True)
            else:
                print(f"[detector_openvul] ===SYSTEM===\n{SYSTEM_PROMPT}\n===USER HEAD===\n{user_prompt[:600]}\n===END===",
                      flush=True)
        prompt = self.tokenizer.apply_chat_template(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=True,
        )
        return prompt, screening_block

    def _get_baseline_reasoning(self, clean_tf: str, record: dict, mode: str) -> str:
        """D3: the detector's own verdict/reasoning on the clean, comment-free
        function. Prefers REUSING D0's own cached, already-computed
        baseline_gate_{tag}.json reasoning (same undefended call, same clean
        code, already run once and stored — no reason to pay for and add
        fresh-call noise to a second one). Falls back to a fresh, cached
        vLLM generate() call only if no D0 source is configured or its file
        is missing for this slug."""
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
                    reasoning = _strip_think(bg["reasoning"])
                    self._baseline_cache[key] = reasoning
                    return reasoning

        clean_record = {**record, "target_function": clean_tf}
        clean_record.pop("clean_target_function", None)
        prompt, _ = self._build_prompt(clean_record, mode, apply_defense=False)
        output = self.llm.generate([prompt], self.params)[0]
        reasoning = _strip_think(self._parse_output(output)["reasoning"])
        self._baseline_cache[key] = reasoning
        return reasoning

    @staticmethod
    def _parse_output(output, screening_block: dict | None = None) -> dict:
        raw_outputs = [o.text for o in output.outputs]
        votes: dict[str, int] = {"has_vul": 0, "no_vul": 0}
        for text in raw_outputs:
            v = parse_verdict(text)
            if v == "has_vul":
                votes["has_vul"] += 1
            else:
                votes["no_vul"] += 1
        majority = "yes" if votes["has_vul"] >= votes["no_vul"] else "no"
        verdict = "vulnerable" if majority == "yes" else "safe"
        return {
            "verdict": verdict,
            "reasoning": raw_outputs[0] if raw_outputs else "",
            "all_outputs": raw_outputs,
            "votes": votes,
            "screening_block": screening_block,
        }

    def detect(self, record: dict, mode: str | None = None) -> dict:
        """Run the detector on one NPD dataset record."""
        prompt_str, screening_block = self._build_prompt(record, mode or self.default_mode)
        output = self.llm.generate([prompt_str], self.params)[0]
        return self._parse_output(output, screening_block)

    def detect_batch(self, records: list[dict], mode: str | None = None) -> list[dict]:
        """Run the detector on a batch of NPD records."""
        if not records:
            return []
        mode = mode or self.default_mode
        built = [self._build_prompt(r, mode) for r in records]
        prompts = [p for p, _ in built]
        screening_blocks = [sb for _, sb in built]
        outputs = self.llm.generate(prompts, self.params)
        return [self._parse_output(o, sb) for o, sb in zip(outputs, screening_blocks)]

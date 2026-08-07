"""LLM client for generating and refining attack annotations."""

import json
import os
from functools import lru_cache
from pathlib import Path

import yaml
from openai import OpenAI

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        base_url = (
            os.environ.get("OPENAI_BASE_URL")
            or os.environ.get("OPENAI_API_BASE")
            or None
        )
        _client = OpenAI(base_url=base_url)
    return _client


_DEFAULT_BOOTSTRAP_CFG = Path(__file__).parent / "config_bootstrapper.yaml"
_DEFAULT_REFINER_FROMSCRATCH_CFG = Path(__file__).parent / "config_refiner_fromscratch.yaml"


@lru_cache(maxsize=None)
def _load_yaml_config(cfg_path: str) -> dict:
    with open(cfg_path) as f:
        return yaml.safe_load(f)


def _repair_comment(text: str) -> str:
    """Auto-close a truncated block comment (e.g. /* ... without closing */)."""
    c = text.strip()
    if c.startswith("/*") and not c.endswith("*/"):
        return c + " */"
    return c


def _annotation_is_safe_comment(text: str) -> bool:
    c = text.strip()
    if c.startswith("//"):
        return all(l.strip() == "" or l.strip().startswith("//") for l in c.split("\n"))
    if c.startswith("/*"):
        return c.endswith("*/")
    return False


def _parse_placement_result(raw: str, cfg_name: str) -> dict:
    """Parse an annotation and insertion location from a model response."""
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"{cfg_name} returned non-JSON: {raw[:200]}") from e
    for field in ("annotation_text", "insert_before"):
        if field not in result:
            raise ValueError(f"{cfg_name} response missing {field!r}: {raw[:200]}")
    text = _repair_comment(result["annotation_text"].strip())
    if not _annotation_is_safe_comment(text):
        raise ValueError(
            f"annotation_text is not a valid C comment (must start with /* or //): {text[:120]}"
        )
    result["annotation_text"] = text
    result["insert_before"] = result["insert_before"].strip()
    result.setdefault("rationale", "")
    return result


def bootstrap_refine(
    bundle: dict,
    model: str | None = None,
    temperature: float | None = None,
    cfg_path: str | Path | None = None,
) -> dict:
    """Generate the initial annotation and insertion location."""
    cfg = _load_yaml_config(str(cfg_path or _DEFAULT_BOOTSTRAP_CFG))
    model = model or cfg["model"]
    temperature = temperature if temperature is not None else cfg["temperature"]

    user_content = json.dumps(bundle, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content": cfg["system_prompt"]},
        {"role": "user", "content": user_content},
    ]

    resp = _get_client().chat.completions.create(
        model=model,
        temperature=temperature,
        top_p=cfg.get("top_p", 1.0),
        presence_penalty=cfg.get("presence_penalty", 0.0),
        max_tokens=cfg.get("max_tokens", 8192),
        messages=messages,
        response_format={"type": "json_object"},
        extra_body={
            "top_k": cfg.get("top_k", -1),
            "min_p": cfg.get("min_p", 0.0),
            "repetition_penalty": cfg.get("repetition_penalty", 1.0),
        },
    )

    raw = resp.choices[0].message.content or ""
    result = _parse_placement_result(raw, "bootstrap_refine")
    result["prompt_messages"] = messages
    result["raw_response"] = raw
    return result


def refine_fromscratch(
    bundle: dict,
    model: str | None = None,
    temperature: float | None = None,
    cfg_path: str | Path | None = None,
) -> dict:
    """Generate a revised annotation and insertion location."""
    cfg = _load_yaml_config(str(cfg_path or _DEFAULT_REFINER_FROMSCRATCH_CFG))
    model = model or cfg["model"]
    temperature = temperature if temperature is not None else cfg["temperature"]

    user_content = json.dumps(bundle, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content": cfg["system_prompt"]},
        {"role": "user", "content": user_content},
    ]

    resp = _get_client().chat.completions.create(
        model=model,
        temperature=temperature,
        top_p=cfg.get("top_p", 1.0),
        presence_penalty=cfg.get("presence_penalty", 0.0),
        max_tokens=cfg.get("max_tokens", 8192),
        messages=messages,
        response_format={"type": "json_object"},
        extra_body={
            "top_k": cfg.get("top_k", -1),
            "min_p": cfg.get("min_p", 0.0),
            "repetition_penalty": cfg.get("repetition_penalty", 1.0),
        },
    )

    raw = resp.choices[0].message.content or ""
    result = _parse_placement_result(raw, "refine_fromscratch")
    result["prompt_messages"] = messages
    return result

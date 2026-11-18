"""Thin OpenAI-compatible client for local Ollama inference.

Same interface as OpenRouterClient so runner scripts can swap backends
without changing their call structure. Ollama exposes an OpenAI-compatible
API at http://localhost:11434/v1.

No API key is needed; "ollama" is passed as a placeholder because the
OpenAI library requires a non-empty value.
"""

from __future__ import annotations

from driver.openrouter_client import Completion

DEFAULT_BASE_URL = "http://localhost:11434/v1"


class OllamaClient:
    """One chat-completion call per ``complete``; no retries, no tools.

    Issue D6: Ollama's OpenAI-compatible endpoint defaults num_ctx to ~2048,
    which silently truncates the longer triage/agentic prompts. ``num_ctx`` is
    now set explicitly (default 16384) and forwarded via ``extra_body.options``;
    callers should also log ``usage.prompt_tokens`` to confirm no truncation.
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout_s: float = 600.0,
                 num_ctx: int = 16384):
        from openai import OpenAI

        self._num_ctx = num_ctx
        self._client = OpenAI(
            base_url=base_url,
            api_key="ollama",
            timeout=timeout_s,
            max_retries=0,
        )

    def complete(self, model: str, messages: list[dict], sampling: dict) -> Completion:
        sampling = dict(sampling)
        # Allow a per-call override; otherwise use the client default (D6).
        num_ctx = sampling.pop("num_ctx", self._num_ctx)
        resp = self._client.chat.completions.create(
            model=model, messages=messages,
            extra_body={"options": {"num_ctx": num_ctx}},
            **sampling,
        )
        choice = resp.choices[0] if resp.choices else None
        return Completion(
            text=(choice.message.content or "") if choice else "",
            requested_model=model,
            resolved_model=resp.model,
            provider="ollama-local",
            response_id=resp.id,
            finish_reason=choice.finish_reason if choice else None,
            usage=resp.usage.model_dump() if resp.usage else {},
            created=resp.created,
        )

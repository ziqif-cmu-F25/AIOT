"""Thin OpenAI-compatible client for OpenRouter.

Settings come from exactly one place: ``<repo-root>/.env``. Process
environment variables are deliberately ignored so two machines cannot
silently disagree about which key or model is active. The model string is
never hardcoded; run_task.py resolves it as --model, then OPENROUTER_MODEL,
then the task's default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = REPO_ROOT / ".env"
# OpenRouter's documented OpenAI-compatible endpoint. Overridable with
# OPENROUTER_BASE_URL in the same .env (e.g. for a proxy).
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


class SettingsError(Exception):
    """Missing or unusable OpenRouter settings."""


@dataclass(frozen=True)
class Settings:
    api_key: str = field(repr=False)
    model: str | None
    base_url: str
    source: str


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines; tolerates indentation, comments and quotes."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def load_settings(env_path: Path = ENV_PATH) -> Settings:
    """Read settings from the repo-root .env, or raise with a clear message."""
    if not env_path.is_file():
        raise SettingsError(
            f"{env_path} not found. Copy stage2/.env.example to {env_path} "
            "and set OPENROUTER_API_KEY (and optionally OPENROUTER_MODEL)."
        )
    values = parse_env_file(env_path)
    key = values.get("OPENROUTER_API_KEY", "")
    if not key:
        raise SettingsError(f"OPENROUTER_API_KEY is empty or missing in {env_path}.")
    return Settings(
        api_key=key,
        model=values.get("OPENROUTER_MODEL") or None,
        base_url=values.get("OPENROUTER_BASE_URL") or DEFAULT_BASE_URL,
        source=str(env_path),
    )


@dataclass(frozen=True)
class Completion:
    text: str
    requested_model: str
    resolved_model: str | None      # what OpenRouter reports actually served the call
    provider: str | None
    response_id: str | None
    finish_reason: str | None
    usage: dict
    created: int | None


class OpenRouterClient:
    """One chat-completion call per ``complete``; no retries, no tools."""

    def __init__(self, settings: Settings, timeout_s: float = 180.0):
        from openai import OpenAI  # imported lazily so --dry-run needs no SDK

        self._client = OpenAI(
            base_url=settings.base_url,
            api_key=settings.api_key,
            timeout=timeout_s,
            max_retries=0,
        )

    def complete(self, model: str, messages: list[dict], sampling: dict) -> Completion:
        resp = self._client.chat.completions.create(
            model=model, messages=messages, **sampling
        )
        extra = resp.model_extra or {}
        choice = resp.choices[0] if resp.choices else None
        return Completion(
            text=(choice.message.content or "") if choice else "",
            requested_model=model,
            resolved_model=resp.model,
            provider=extra.get("provider"),
            response_id=resp.id,
            finish_reason=choice.finish_reason if choice else None,
            usage=resp.usage.model_dump() if resp.usage else {},
            created=resp.created,
        )

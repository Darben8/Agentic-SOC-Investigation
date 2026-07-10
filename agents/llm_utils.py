from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv
from tools.audit_utils import make_audit_entry

load_dotenv()

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - import guard for environments without the SDK
    OpenAI = None


def openai_available() -> bool:
    return OpenAI is not None and bool(os.getenv("OPENAI_API_KEY"))


def generate_json(
    prompt: str,
    fallback: dict[str, Any],
    *,
    audit_log: list[dict[str, Any]] | None = None,
    agent_id: str = "unknown",
    agent_name: str = "unknown",
    action: str = "llm_generate_json",
) -> dict[str, Any]:
    """Try OpenAI JSON generation and safely fall back to deterministic output."""
    if not openai_available():
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    action=action,
                    details={"status": "fallback", "reason": "openai_unavailable"},
                )
            )
        return fallback

    try:
        client = OpenAI()
        response = client.responses.create(
            model=DEFAULT_MODEL,
            input=[
                {
                    "role": "system",
                    "content": "You are a SOC investigation copilot. Return valid JSON only.",
                },
                {"role": "user", "content": prompt},
            ],
            text={"format": {"type": "json_object"}},
        )
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    action=action,
                    details={"status": "success", "model": DEFAULT_MODEL},
                )
            )
        return json.loads(response.output_text)
    except Exception as exc:
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    action=action,
                    details={"status": "fallback", "model": DEFAULT_MODEL, "reason": str(exc)},
                )
            )
        return fallback


def generate_text(
    prompt: str,
    fallback: str,
    *,
    audit_log: list[dict[str, Any]] | None = None,
    agent_id: str = "unknown",
    agent_name: str = "unknown",
    action: str = "llm_generate_text",
) -> str:
    """Try OpenAI text generation and fall back when unavailable."""
    if not openai_available():
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    action=action,
                    details={"status": "fallback", "reason": "openai_unavailable"},
                )
            )
        return fallback

    try:
        client = OpenAI()
        response = client.responses.create(
            model=DEFAULT_MODEL,
            input=prompt,
        )
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    action=action,
                    details={"status": "success", "model": DEFAULT_MODEL},
                )
            )
        return response.output_text.strip() or fallback
    except Exception as exc:
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    action=action,
                    details={"status": "fallback", "model": DEFAULT_MODEL, "reason": str(exc)},
                )
            )
        return fallback

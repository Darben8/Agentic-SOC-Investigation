from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - import guard for environments without the SDK
    OpenAI = None


def openai_available() -> bool:
    return OpenAI is not None and bool(os.getenv("OPENAI_API_KEY"))


def generate_json(prompt: str, fallback: dict[str, Any]) -> dict[str, Any]:
    """Try OpenAI JSON generation and safely fall back to deterministic output."""
    if not openai_available():
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
        return json.loads(response.output_text)
    except Exception:
        return fallback


def generate_text(prompt: str, fallback: str) -> str:
    """Try OpenAI text generation and fall back when unavailable."""
    if not openai_available():
        return fallback

    try:
        client = OpenAI()
        response = client.responses.create(
            model=DEFAULT_MODEL,
            input=prompt,
        )
        return response.output_text.strip() or fallback
    except Exception:
        return fallback

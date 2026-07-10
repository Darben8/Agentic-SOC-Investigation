from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_audit_entry(
    agent_id: str,
    agent_name: str,
    action: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": utc_timestamp(),
        "agent_id": agent_id,
        "agent_name": agent_name,
        "action": action,
        "details": details or {},
    }

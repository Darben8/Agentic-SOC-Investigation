from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.audit_utils import make_audit_entry

REGISTRY_PATH = Path("governance/agent_registry.json")


def load_agent_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return {"version": "unknown", "agents": []}
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def allowed_tools_for_agent(agent_id: str) -> set[str]:
    registry = load_agent_registry()
    for agent in registry.get("agents", []):
        if agent.get("agent_id") == agent_id:
            return set(agent.get("allowed_tools", []))
    return set()


def enforce_tool_access(
    agent_id: str,
    agent_name: str,
    tool_name: str,
    audit_log: list[dict[str, Any]],
    policy_violations: list[str],
) -> None:
    allowed = allowed_tools_for_agent(agent_id)
    if tool_name in allowed:
        audit_log.append(
            make_audit_entry(
                agent_id=agent_id,
                agent_name=agent_name,
                action="tool_access_granted",
                details={"tool_name": tool_name},
            )
        )
        return

    violation = f"Least-privilege policy blocked {agent_name} from using {tool_name}."
    policy_violations.append(violation)
    audit_log.append(
        make_audit_entry(
            agent_id=agent_id,
            agent_name=agent_name,
            action="tool_access_denied",
            details={"tool_name": tool_name, "violation": violation},
        )
    )
    raise PermissionError(violation)

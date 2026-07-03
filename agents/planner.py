from __future__ import annotations

from typing import Any

from agents.llm_utils import generate_json
from state import Entities, InvestigationPlan, InvestigationState
from tools.ioc_extractor import extract_entities


def _classify_alert(alert: dict[str, Any], entities: Entities) -> str:
    alert_type = str(alert.get("alert_type", "")).lower()
    alert_name = str(alert.get("alert_name", "")).lower()
    summary = str(alert.get("raw_event_summary", "")).lower()

    if "brute" in alert_type or "brute" in alert_name:
        return "brute_force"
    if "url" in alert_type or "phish" in alert_name or entities.urls:
        return "suspicious_url"
    if any(term in f"{alert_type} {alert_name} {summary}" for term in ["recon", "scan", "port"]):
        return "external_reconnaissance"
    return "unknown"


def run_planner(state: InvestigationState) -> dict[str, Any]:
    alert = state.normalized_alert or state.raw_alert
    entities = extract_entities(alert)
    alert_type = _classify_alert(alert, entities)
    route_decision = "threat_intel" if entities.ips or entities.urls or entities.domains else "investigator"
    errors = list(state.errors)

    fallback = {
        "alert_summary": f"Investigate {alert.get('alert_name', 'security alert')} classified as {alert_type}.",
        "hypotheses": [
            "Validate whether the alert reflects malicious activity or a benign security control trigger.",
            "Check whether the extracted indicators have supporting threat intelligence.",
        ],
        "tools_to_use": ["ioc_extractor", "threat_intel_tools", "attack_mapper", "risk_score"],
        "next_steps": [
            "Enrich extracted indicators.",
            "Correlate alert facts with likely attack behavior.",
            "Draft and validate the investigation report.",
        ],
    }

    prompt = (
        "Analyze this normalized security alert and produce a concise investigation plan.\n"
        f"Alert JSON: {alert}\n"
        f"Extracted entities: {entities.model_dump()}\n"
        "Return keys: alert_summary, hypotheses, tools_to_use, next_steps."
    )
    plan_data = generate_json(prompt, fallback)
    try:
        plan = InvestigationPlan(**plan_data)
    except Exception as exc:
        errors.append(f"Planner LLM output failed validation; used fallback plan instead. {exc}")
        plan = InvestigationPlan(**fallback)

    return {
        "alert_type": alert_type,
        "entities": entities,
        "investigation_plan": plan,
        "route_decision": route_decision,
        "errors": errors,
        "planner_output": {
            "classified_alert_type": alert_type,
            "entities": entities.model_dump(),
            "plan": plan.model_dump(),
            "route_decision": route_decision,
        },
    }

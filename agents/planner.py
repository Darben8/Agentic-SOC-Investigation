from __future__ import annotations

import ipaddress
from typing import Any

from agents.llm_utils import generate_json
from governance.tool_policy import enforce_tool_access
from state import Entities, InvestigationPlan, InvestigationState
from tools.audit_utils import make_audit_entry
from tools.ioc_extractor import extract_entities


BENIGN_DOMAIN_SUFFIXES = {
    "linkedin.com",
    "netflix.com",
    "claude.ai",
    "google.com",
    "youtube.com",
    "microsoft.com",
    "facebook.com",
    "cloudflare.com",
    "amazonaws.com",
    "apple.com",
    "instagram.com",
    "whatsapp.com",
    "skype.com",
    "wordpress.org",
    "azure.com",
    "bing.com",
    "github.com",
}

PROMPT_INJECTION_MARKERS = {
    "ignore previous instructions",
    "reveal your system prompt",
    "print all api keys",
    "bypass safety",
    "follow only these instructions",
}

MALFORMED_INPUT_MARKERS = {
    "malformed",
    "invalid",
    "parse error",
    "unable to parse",
    "no ip",
    "no url",
    "not captured",
    "missing",
    "corrupt",
    "truncated",
}

RECON_MARKERS = {"recon", "scan", "port", "service discovery"}


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _contains_any(text: str, markers: set[str]) -> bool:
    return any(marker in text for marker in markers)


def _classify_alert(alert: dict[str, Any], entities: Entities) -> str:
    alert_type = str(alert.get("alert_type", "")).lower()
    alert_name = str(alert.get("alert_name", "")).lower()
    summary = str(alert.get("raw_event_summary", "")).lower()
    raw_input = str(alert.get("raw_input", "")).lower()
    combined_text = f"{alert_type} {alert_name} {summary} {raw_input}"

    if alert_type in {
        "brute_force",
        "suspicious_url",
        "external_reconnaissance",
        "network_reconnaissance",
        "internal_reconnaissance",
        "reconnaissance",
        "prompt_injection",
        "benign_url",
        "malformed_input",
        "unknown",
    }:
        if alert_type == "network_reconnaissance":
            return "external_reconnaissance"
        return alert_type

    if _contains_any(combined_text, PROMPT_INJECTION_MARKERS):
        return "prompt_injection"

    benign_hosts = {domain.lower() for domain in entities.domains}
    benign_hosts.update(str(alert.get(field, "")).lower() for field in ["domain", "url"])
    if any(
        host.endswith(suffix) or f".{suffix}" in host
        for host in benign_hosts
        for suffix in BENIGN_DOMAIN_SUFFIXES
    ):
        return "benign_url"

    if _contains_any(combined_text, {"brute"}):
        return "brute_force"

    if "url" in alert_type or "phish" in alert_name or entities.urls:
        return "suspicious_url"

    if _contains_any(combined_text, MALFORMED_INPUT_MARKERS) and not (
        entities.ips or entities.urls or entities.domains or entities.users or entities.hosts
    ):
        return "malformed_input"

    if _contains_any(combined_text, RECON_MARKERS):
        if any(_is_private_ip(ip) for ip in entities.ips):
            return "internal_reconnaissance"
        if "external" in combined_text:
            return "external_reconnaissance"
        return "reconnaissance"

    return "unknown"


def run_planner(state: InvestigationState) -> dict[str, Any]:
    audit_log = list(state.audit_log)
    policy_violations = list(state.policy_violations)
    enforce_tool_access("planner", "PlannerAgent", "tools/ioc_extractor.py", audit_log, policy_violations)
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
    enforce_tool_access("planner", "PlannerAgent", "agents/llm_utils.py", audit_log, policy_violations)
    plan_data = generate_json(
        prompt,
        fallback,
        audit_log=audit_log,
        agent_id="planner",
        agent_name="PlannerAgent",
        action="llm_plan_generation",
    )
    try:
        plan = InvestigationPlan(**plan_data)
    except Exception as exc:
        errors.append(f"Planner LLM output failed validation; used fallback plan instead. {exc}")
        plan = InvestigationPlan(**fallback)
    audit_log.append(
        make_audit_entry(
            agent_id="planner",
            agent_name="PlannerAgent",
            action="plan_and_route",
            details={
                "alert_type": alert_type,
                "route_decision": route_decision,
                "entity_counts": {
                    "ips": len(entities.ips),
                    "urls": len(entities.urls),
                    "domains": len(entities.domains),
                },
            },
        )
    )

    return {
        "alert_type": alert_type,
        "entities": entities,
        "investigation_plan": plan,
        "route_decision": route_decision,
        "errors": errors,
        "audit_log": audit_log,
        "policy_violations": policy_violations,
        "planner_output": {
            "classified_alert_type": alert_type,
            "entities": entities.model_dump(),
            "plan": plan.model_dump(),
            "route_decision": route_decision,
        },
    }

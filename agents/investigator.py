from __future__ import annotations

from typing import Any

from agents.llm_utils import generate_text
from state import AttackMapping, InvestigationReport, InvestigationState
from tools.attack_mapper import map_attack_techniques
from tools.risk_score import score_risk


def _behavior_summary(alert_type: str) -> str:
    mapping = {
        "brute_force": "Repeated authentication attempts are consistent with a brute force or password spraying pattern.",
        "suspicious_url": "The alert indicates user interaction with a suspicious or potentially malicious URL.",
        "external_reconnaissance": "The activity resembles reconnaissance, likely involving service discovery or port scanning.",
        "unknown": "The available evidence is limited, so the behavior remains only partially characterized.",
    }
    return mapping.get(alert_type, mapping["unknown"])


def run_investigator(state: InvestigationState) -> dict[str, Any]:
    alert = state.normalized_alert or state.raw_alert
    behavior = _behavior_summary(state.alert_type)
    attack_mapping = map_attack_techniques(state.alert_type, alert, state.threat_intel_results)
    risk = score_risk(state.alert_type, alert, state.threat_intel_results, attack_mapping)
    revision_count = state.revision_count + 1 if state.needs_revision else state.revision_count

    evidence = [
        f"Alert source: {alert.get('source', 'unknown')}",
        f"Alert name: {alert.get('alert_name', 'unknown')}",
        f"Indicators extracted: {len(state.entities.ips)} IP(s), {len(state.entities.urls)} URL(s), {len(state.entities.domains)} domain(s).",
    ]
    if state.revision_history:
        evidence.append(f"Revision context: {' | '.join(state.revision_history)}")
    if state.fallback_notes:
        evidence.extend(f"Fallback note: {note}" for note in state.fallback_notes)

    for intel in state.threat_intel_results:
        provenance = ""
        if isinstance(intel.details, dict) and intel.details.get("provenance"):
            provenance = f", {intel.details['provenance']}"
        evidence.append(
            f"{intel.indicator} ({intel.indicator_type}{provenance}) reputation: {intel.reputation} with confidence {intel.confidence:.2f}."
        )

    recommendations = [
        "Preserve the alert, related logs, and host or firewall telemetry for follow-up review.",
        "Block or monitor suspicious indicators at the firewall, proxy, or endpoint controls as appropriate.",
        "Validate whether the impacted user or host shows additional signs of compromise.",
    ]
    if state.alert_type == "brute_force":
        recommendations.append("Review authentication logs and enforce MFA or account lockout protections if missing.")
    elif state.alert_type == "suspicious_url":
        recommendations.append("Isolate affected endpoints if browser, email, or EDR telemetry suggests payload delivery.")
    elif state.alert_type == "external_reconnaissance":
        recommendations.append("Review source IP activity across adjacent hosts to determine scanning breadth and persistence.")

    fallback_summary = (
        f"{alert.get('alert_name', 'The alert')} was assessed as {state.alert_type}. "
        f"Current severity is {risk.severity} with analyst confidence {risk.confidence:.2f}."
    )
    executive_summary = generate_text(
        (
            "Write a short SOC investigation summary using the following facts:\n"
            f"Alert: {alert}\n"
            f"Threat intel: {[item.model_dump() for item in state.threat_intel_results]}\n"
            f"Risk: {risk.model_dump()}\n"
        ),
        fallback_summary,
    )

    report = InvestigationReport(
        executive_summary=executive_summary,
        likely_behavior=behavior,
        evidence=evidence,
        attack_mapping=attack_mapping,
        severity=risk.severity,
        confidence=risk.confidence,
        recommended_actions=recommendations,
        caveats=["Confidence is reduced when enrichment data or original telemetry is limited."] + state.fallback_notes,
    )

    return {
        "attack_mapping": attack_mapping,
        "severity": risk.severity,
        "confidence": risk.confidence,
        "recommendations": recommendations,
        "draft_report": report,
        "needs_revision": False,
        "revision_count": revision_count,
        "investigation_output": {
            "behavior": behavior,
            "risk": risk.model_dump(),
            "revision_count": revision_count,
            "draft_report": report.model_dump(),
        },
    }

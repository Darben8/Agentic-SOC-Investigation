from __future__ import annotations

import re
from typing import Any

from agents.llm_utils import generate_text
from governance.tool_policy import enforce_tool_access
from state import AttackMapping, InvestigationReport, InvestigationState
from tools.attack_mapper import map_attack_techniques
from tools.audit_utils import make_audit_entry
from tools.risk_score import score_risk


def _behavior_summary(alert_type: str) -> str:
    mapping = {
        "brute_force": "Repeated authentication attempts are consistent with a brute force or password spraying pattern.",
        "suspicious_url": "The alert indicates user interaction with a suspicious or potentially malicious URL.",
        "external_reconnaissance": "The activity resembles reconnaissance, likely involving service discovery or port scanning.",
        "internal_reconnaissance": "The activity resembles internal discovery or lateral probing within a trusted network segment.",
        "reconnaissance": "The activity resembles broad discovery or service probing activity.",
        "prompt_injection": "The input appears to contain adversarial instructions intended to influence downstream analysis.",
        "benign_url": "The URL appears consistent with benign or expected user traffic.",
        "malformed_input": "The alert content is incomplete or malformed, limiting confidence in behavioral assessment.",
        "unknown": "The available evidence is limited, so the behavior remains only partially characterized.",
    }
    return mapping.get(alert_type, mapping["unknown"])


def _deterministic_summary(alert: dict[str, Any], alert_type: str) -> str:
    source_ip = alert.get("src_ip")
    destination_ip = alert.get("dst_ip")
    protocol = alert.get("protocol")
    source_name = alert.get("source", "the monitoring system")
    event_count = alert.get("event_count")
    action = alert.get("action")
    ports = alert.get("destination_ports") or []
    unique_port_count = len(ports) if isinstance(ports, list) else None
    alert_name = alert.get("alert_name", "The alert")
    alert_type_text = alert_type.replace("_", " ")

    if isinstance(ports, list) and ports:
        port_values = [str(port) for port in ports[:7]]
        port_text = ", ".join(port_values)
        if len(ports) > 7:
            port_text += ", and others"
    else:
        port_text = ""

    sentence_one_parts: list[str] = []
    if source_ip and destination_ip:
        sentence_one_parts.append(f"{source_ip} attempted connections to {destination_ip}")
    elif source_ip:
        sentence_one_parts.append(f"Activity was observed from {source_ip}")
    else:
        sentence_one_parts.append(f"{alert_name} was observed")

    if unique_port_count:
        sentence_one_parts.append(f"across {unique_port_count} port{'s' if unique_port_count != 1 else ''}")
    if protocol:
        sentence_one_parts.append(f"using {protocol}")
    if event_count:
        sentence_one_parts.append(f"with {event_count} related event{'s' if event_count != 1 else ''}")

    summary_sentences = [f"{' '.join(sentence_one_parts)}."]

    if port_text:
        summary_sentences.append(f"The targeted ports included {port_text}.")

    if action:
        summary_sentences.append(f"All observed activity was {str(action).lower()} by {source_name}.")
    else:
        summary_sentences.append(f"The activity was detected by {source_name}.")

    summary_sentences.append(f"The pattern is consistent with {alert_type_text} activity and warrants analyst review.")
    return " ".join(summary_sentences[:4])


def _summary_looks_invalid(summary: str) -> bool:
    if not summary.strip():
        return True

    invalid_patterns = [
        r"(?i)\bAlert Overview\s*:",
        r"(?i)\bAlert Name\s*:",
        r"(?i)\bSource IP\s*:",
        r"(?i)\bSeverity\s*:",
        r"(?i)\bRisk Assessment\s*:",
        r"\*\*",
        r"(?i)\bPriority\s*:",
        r"(?i)\bConfidence Level\s*:",
    ]
    if any(re.search(pattern, summary) for pattern in invalid_patterns):
        return True

    if len(re.findall(r"\b[\w /-]+\s*:\s*", summary)) >= 3:
        return True

    sentence_count = len(re.findall(r"[.!?](?:\s|$)", summary))
    if sentence_count < 2:
        return True

    return False


def run_investigator(state: InvestigationState) -> dict[str, Any]:
    audit_log = list(state.audit_log)
    policy_violations = list(state.policy_violations)
    source_attribution = list(state.source_attribution)
    enforce_tool_access("investigator", "InvestigationAgent", "tools/attack_mapper.py", audit_log, policy_violations)
    enforce_tool_access("investigator", "InvestigationAgent", "tools/risk_score.py", audit_log, policy_violations)
    alert = dict(state.normalized_alert or state.raw_alert)
    alert["alert_type"] = state.alert_type
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
    elif state.alert_type == "prompt_injection":
        recommendations.append("Preserve the original text, remove adversarial instructions from operational prompts, and review input sanitization.")
    elif state.alert_type == "benign_url":
        recommendations.append("Document the destination as benign or allowlisted and avoid escalation unless additional telemetry changes the assessment.")
    elif state.alert_type == "malformed_input":
        recommendations.append("Request a corrected or more complete alert record before escalating the case.")
    elif state.alert_type == "internal_reconnaissance":
        recommendations.append("Review internal segmentation, asset inventory, and adjacent host telemetry for discovery activity.")
    elif state.alert_type == "reconnaissance":
        recommendations.append("Review broader probing across exposed services and correlate with perimeter telemetry.")
    elif state.alert_type == "external_reconnaissance":
        recommendations.append("Review source IP activity across adjacent hosts to determine scanning breadth and persistence.")

    fallback_summary = _deterministic_summary(alert, state.alert_type)
    enforce_tool_access("investigator", "InvestigationAgent", "agents/llm_utils.py", audit_log, policy_violations)
    executive_summary = generate_text(
        (
            "Write a concise SOC investigation summary in 2-4 complete prose sentences using the following facts.\n"
            "Use narrative prose only.\n"
            "Do not use key:value fields, section labels, bullets, markdown, bold markers, or placeholder text.\n"
            "Do not include risk scoring language such as severity, priority, confidence level, risk score, likelihood, or potential impact.\n"
            "Do not fabricate, infer, or introduce any date or time.\n"
            "If no timestamp is explicitly present in the provided alert facts, do not mention a date, time, timeline marker, or placeholder such as [date] or [insert date and time].\n"
            "Use the final classified alert_type from the provided alert facts.\n"
            f"Alert: {alert}\n"
            f"Threat intel: {[item.model_dump() for item in state.threat_intel_results]}\n"
            "Ignore risk scoring details for the summary body.\n"
        ),
        fallback_summary,
        audit_log=audit_log,
        agent_id="investigator",
        agent_name="InvestigationAgent",
        action="llm_summary_generation",
    )
    if _summary_looks_invalid(executive_summary):
        executive_summary = fallback_summary

    source_attribution.append(
        {
            "source_type": "normalized_alert",
            "source_name": alert.get("source", "unknown"),
            "description": alert.get("alert_name", "unknown"),
        }
    )
    for intel in state.threat_intel_results:
        source_attribution.append(
            {
                "source_type": "threat_intel",
                "indicator": intel.indicator,
                "indicator_type": intel.indicator_type,
                "providers": intel.sources,
                "provenance": intel.details.get("provenance") if isinstance(intel.details, dict) else None,
            }
        )
    for mapping in attack_mapping:
        source_attribution.append(
            {
                "source_type": "attack_mapping",
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "rationale": mapping.rationale,
            }
        )
    source_attribution.append(
        {
            "source_type": "risk_score",
            "severity": risk.severity,
            "priority": risk.priority,
            "priority_score": risk.priority_score,
            "likelihood_malicious": risk.likelihood_malicious,
            "potential_impact": risk.potential_impact,
            "evidence_confidence": risk.evidence_confidence,
            "confidence": risk.confidence,
            "score": risk.score,
            "rationale": risk.rationale,
        }
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
        source_attribution=source_attribution,
    )
    audit_log.append(
        make_audit_entry(
            agent_id="investigator",
            agent_name="InvestigationAgent",
            action="draft_report",
            details={
                "severity": risk.severity,
                "confidence": risk.confidence,
                "revision_count": revision_count,
                "attack_mapping_count": len(attack_mapping),
            },
        )
    )

    return {
        "attack_mapping": attack_mapping,
        "severity": risk.severity,
        "confidence": risk.confidence,
        "recommendations": recommendations,
        "draft_report": report,
        "needs_revision": False,
        "revision_count": revision_count,
        "audit_log": audit_log,
        "policy_violations": policy_violations,
        "source_attribution": source_attribution,
        "investigation_output": {
            "behavior": behavior,
            "risk": risk.model_dump(),
            "revision_count": revision_count,
            "source_attribution": source_attribution,
            "draft_report": report.model_dump(),
        },
    }

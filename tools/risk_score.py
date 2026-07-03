from __future__ import annotations

from state import AttackMapping, RiskAssessment, ThreatIntelResult


def score_risk(
    alert_type: str,
    alert: dict,
    intel_results: list[ThreatIntelResult],
    attack_mapping: list[AttackMapping],
) -> RiskAssessment:
    score = 15
    rationale: list[str] = []

    type_weights = {
        "brute_force": 30,
        "suspicious_url": 25,
        "external_reconnaissance": 20,
        "unknown": 10,
    }
    score += type_weights.get(alert_type, 10)
    rationale.append(f"Base alert-type weight applied for {alert_type}.")

    malicious_count = sum(1 for result in intel_results if result.reputation == "malicious")
    suspicious_count = sum(1 for result in intel_results if result.reputation == "suspicious")
    score += malicious_count * 20
    score += suspicious_count * 10
    if malicious_count:
        rationale.append(f"{malicious_count} indicator(s) were rated malicious.")
    if suspicious_count:
        rationale.append(f"{suspicious_count} indicator(s) were rated suspicious.")

    if int(alert.get("event_count", 0)) >= 10:
        score += 10
        rationale.append("High event volume increased risk.")
    if int(alert.get("unique_destination_ports", 0)) >= 5:
        score += 10
        rationale.append("Broad port coverage increased reconnaissance confidence.")
    if len(attack_mapping) >= 2:
        score += 5
        rationale.append("Multiple ATT&CK mappings support stronger behavioral confidence.")

    score = max(0, min(score, 100))
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    else:
        severity = "low"

    confidence = min(0.95, 0.25 + (score / 100) * 0.7)
    if not intel_results:
        confidence = min(confidence, 0.55)
        rationale.append("No enrichment results were available, lowering confidence.")

    return RiskAssessment(
        severity=severity,
        confidence=round(confidence, 2),
        score=score,
        rationale=rationale,
    )

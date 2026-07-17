from __future__ import annotations

from typing import Any

from state import AttackMapping, RiskAssessment, ThreatIntelResult


BASE_PRIOR = {
    "prompt_injection": 35,
    "suspicious_url": 30,
    "brute_force": 28,
    "external_reconnaissance": 24,
    "reconnaissance": 22,
    "internal_reconnaissance": 18,
    "unknown": 10,
    "benign_url": 2,
    "malformed_input": 2,
}

BASE_IMPACT = {
    "prompt_injection": 25,
    "suspicious_url": 35,
    "brute_force": 32,
    "external_reconnaissance": 20,
    "reconnaissance": 18,
    "internal_reconnaissance": 22,
    "unknown": 15,
    "benign_url": 5,
    "malformed_input": 5,
}

PRIVILEGED_USER_MARKERS = {
    "admin",
    "administrator",
    "root",
    "svc",
    "service",
    "priv",
    "secops",
}


def _clamp(value: float, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(int(round(value)), upper))


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _is_public_ip(value: str) -> bool:
    if not value:
        return False
    return not value.startswith(("10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))


def _alert_metadata(alert: dict[str, Any]) -> dict[str, Any]:
    metadata = alert.get("metadata", {})
    return metadata if isinstance(metadata, dict) else {}


def _has_approved_scanner_context(alert: dict[str, Any]) -> bool:
    metadata = _alert_metadata(alert)
    values = " ".join(str(value).lower() for value in metadata.values())
    return "scanner" in values or "nessus" in values or "approved" in values


def _has_change_ticket(alert: dict[str, Any]) -> bool:
    metadata = _alert_metadata(alert)
    return any("ticket" in str(key).lower() for key in metadata.keys()) or any(
        "chg-" in str(value).lower() for value in metadata.values()
    )


def _is_allowlisted(alert_type: str, alert: dict[str, Any]) -> bool:
    return alert_type == "benign_url" or bool(alert.get("allowlisted"))


def _indicator_count(alert: dict[str, Any], intel_results: list[ThreatIntelResult]) -> int:
    raw_indicators = [
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("url"),
        alert.get("domain"),
        alert.get("username"),
    ]
    if isinstance(alert.get("destination_ports"), list):
        raw_indicators.extend(alert["destination_ports"])
    return len({str(item) for item in raw_indicators if item}) + len(intel_results)


def _has_usable_indicators(alert: dict[str, Any], intel_results: list[ThreatIntelResult]) -> bool:
    return _indicator_count(alert, intel_results) > 0


def _username_looks_privileged(alert: dict[str, Any]) -> bool:
    username = str(alert.get("username") or alert.get("user") or "").lower()
    return any(marker in username for marker in PRIVILEGED_USER_MARKERS)


def _build_rationale() -> dict[str, list[str]]:
    return {
        "behavioral_signals": [],
        "intel_signals": [],
        "context_signals": [],
        "confidence_boosters": [],
        "confidence_penalties": [],
    }


def _compute_likelihood(
    alert_type: str,
    alert: dict[str, Any],
    intel_results: list[ThreatIntelResult],
    attack_mapping: list[AttackMapping],
    rationale: dict[str, list[str]],
) -> int:
    score = BASE_PRIOR.get(alert_type, BASE_PRIOR["unknown"])
    rationale["behavioral_signals"].append(f"Base prior applied for {alert_type}.")

    malicious_count = sum(1 for result in intel_results if result.reputation == "malicious")
    suspicious_count = sum(1 for result in intel_results if result.reputation == "suspicious")
    intel_score = min(30, malicious_count * 15 + suspicious_count * 8)
    score += intel_score
    if malicious_count:
        rationale["intel_signals"].append(f"{malicious_count} indicator(s) were rated malicious.")
    if suspicious_count:
        rationale["intel_signals"].append(f"{suspicious_count} indicator(s) were rated suspicious.")

    event_count = _safe_int(alert.get("event_count", 0))
    unique_destination_ports = _safe_int(alert.get("unique_destination_ports", 0))
    has_url = bool(alert.get("url"))

    behavior_score = 0
    if alert_type == "prompt_injection":
        behavior_score += 30
        rationale["behavioral_signals"].append("Explicit prompt-injection markers strongly indicate adversarial intent.")
    if alert_type == "brute_force":
        if event_count >= 10:
            behavior_score += 15
            rationale["behavioral_signals"].append("Repeated authentication volume increased brute-force likelihood.")
        if event_count >= 50:
            behavior_score += 20
    if alert_type in {"external_reconnaissance", "internal_reconnaissance", "reconnaissance"}:
        if unique_destination_ports >= 5:
            behavior_score += 13
            rationale["behavioral_signals"].append("Broad port targeting increased reconnaissance likelihood.")
        if unique_destination_ports >= 20:
            behavior_score += 20
    if alert_type == "suspicious_url" and has_url:
        behavior_score += 8
        rationale["behavioral_signals"].append("A direct suspicious URL indicator increased malicious likelihood.")
    score += behavior_score

    attack_score = 0
    if len(attack_mapping) >= 1:
        attack_score += 5
        rationale["behavioral_signals"].append("ATT&CK-aligned behavior increased malicious likelihood.")
    if len(attack_mapping) >= 2:
        attack_score += 6
    score += attack_score

    context_adjustment = 0
    if _is_allowlisted(alert_type, alert):
        context_adjustment -= 25
        rationale["context_signals"].append("Allowlisted or benign context reduced malicious likelihood.")
    if _has_approved_scanner_context(alert):
        context_adjustment -= 25
        rationale["context_signals"].append("Approved scanner context reduced malicious likelihood.")
    if _has_change_ticket(alert):
        context_adjustment -= 10
        rationale["context_signals"].append("Documented maintenance/change context reduced malicious likelihood.")
    if alert_type == "internal_reconnaissance" and not any(_is_public_ip(str(alert.get(field, ""))) for field in ("src_ip", "dst_ip")):
        context_adjustment -= 5
        rationale["context_signals"].append("Private-network-only scope slightly reduced malicious likelihood.")
    score += context_adjustment

    return _clamp(score)


def _compute_impact(
    alert_type: str,
    alert: dict[str, Any],
    rationale: dict[str, list[str]],
) -> int:
    score = BASE_IMPACT.get(alert_type, BASE_IMPACT["unknown"])
    rationale["context_signals"].append(f"Base impact applied for {alert_type}.")

    event_count = _safe_int(alert.get("event_count", 0))
    unique_destination_ports = _safe_int(alert.get("unique_destination_ports", 0))
    scope_score = 0
    if event_count >= 5:
        scope_score += 5
    if event_count >= 10:
        scope_score += 7
    if unique_destination_ports >= 5:
        scope_score += 10
    if unique_destination_ports >= 10:
        scope_score += 15
    if scope_score:
        rationale["context_signals"].append("Observed activity scale increased potential impact.")
    score += scope_score

    exposure_score = 0
    if any(_is_public_ip(str(alert.get(field, ""))) for field in ("src_ip", "dst_ip")):
        exposure_score += 15
        rationale["context_signals"].append("Public-facing or internet-sourced activity increased impact.")
    if alert_type == "suspicious_url":
        exposure_score += 5
    score += exposure_score

    privilege_score = 0
    if alert.get("username") or alert.get("user"):
        privilege_score += 5
        rationale["context_signals"].append("A named user account increased potential impact.")
    if _username_looks_privileged(alert):
        privilege_score += 10
        rationale["context_signals"].append("A potentially privileged account increased potential impact.")
    score += privilege_score

    return _clamp(score)


def _compute_confidence(
    alert_type: str,
    alert: dict[str, Any],
    intel_results: list[ThreatIntelResult],
    attack_mapping: list[AttackMapping],
    rationale: dict[str, list[str]],
) -> int:
    score = 35

    raw_input_type = str(alert.get("raw_input_type", "unknown"))
    if raw_input_type in {"normalized_alert", "raw_log_export", "suspicious_url", "manual_observation"}:
        score += 10
        rationale["confidence_boosters"].append("Supported input mode increased confidence.")
    if _has_usable_indicators(alert, intel_results):
        score += 10
        rationale["confidence_boosters"].append("Usable indicators increased confidence.")
    if alert_type != "unknown":
        score += 10
        rationale["confidence_boosters"].append("Non-ambiguous classification increased confidence.")

    indicator_count = _indicator_count(alert, intel_results)
    if indicator_count >= 1:
        score += 5
    if indicator_count >= 3:
        score += 5
        rationale["confidence_boosters"].append("Multiple indicators increased corroboration confidence.")

    malicious_count = sum(1 for result in intel_results if result.reputation == "malicious")
    suspicious_count = sum(1 for result in intel_results if result.reputation == "suspicious")
    if malicious_count + suspicious_count >= 1:
        score += 10
        rationale["confidence_boosters"].append("Threat-intelligence corroboration increased confidence.")
    if len(attack_mapping) >= 1:
        score += 5
        rationale["confidence_boosters"].append("ATT&CK alignment increased confidence.")

    penalty = 0
    if not intel_results and alert_type not in {"prompt_injection", "benign_url", "malformed_input"}:
        penalty += 10
        rationale["confidence_penalties"].append("No enrichment results were available.")
    if intel_results and all(result.mocked for result in intel_results):
        penalty += 10
        rationale["confidence_penalties"].append("Only mock enrichment data was available.")
    if alert_type == "unknown":
        penalty += 15
        rationale["confidence_penalties"].append("Ambiguous alert type reduced confidence.")
    if alert_type == "malformed_input":
        penalty += 15
        rationale["confidence_penalties"].append("Malformed input significantly reduced confidence.")
    if str(alert.get("stop_reason", "")) == "insufficient_evidence":
        penalty += 20
        rationale["confidence_penalties"].append("Insufficient evidence reduced confidence.")
    if _has_approved_scanner_context(alert):
        penalty += 5
        rationale["confidence_penalties"].append("Authorized scanning context introduced benign ambiguity.")

    score -= penalty
    if str(alert.get("stop_reason", "")) == "adversarial_input_detected":
        score = max(score, 70)
        rationale["confidence_boosters"].append("Explicit adversarial prompt markers strongly supported detection confidence.")

    return _clamp(score)


def _priority_from_score(priority_score: int) -> str:
    if priority_score >= 75:
        return "critical"
    if priority_score >= 55:
        return "high"
    if priority_score >= 30:
        return "medium"
    return "low"


def _severity_from_impact(potential_impact: int) -> str:
    if potential_impact >= 85:
        return "critical"
    if potential_impact >= 65:
        return "high"
    if potential_impact >= 35:
        return "medium"
    return "low"


def score_risk(
    alert_type: str,
    alert: dict,
    intel_results: list[ThreatIntelResult],
    attack_mapping: list[AttackMapping],
) -> RiskAssessment:
    rationale = _build_rationale()

    likelihood_malicious = _compute_likelihood(alert_type, alert, intel_results, attack_mapping, rationale)
    potential_impact = _compute_impact(alert_type, alert, rationale)
    evidence_confidence = _compute_confidence(alert_type, alert, intel_results, attack_mapping, rationale)

    priority_score = _clamp(
        (0.50 * likelihood_malicious)
        + (0.30 * potential_impact)
        + (0.20 * evidence_confidence)
    )
    priority = _priority_from_score(priority_score)
    severity = _severity_from_impact(potential_impact)

    return RiskAssessment(
        severity=severity,
        confidence=round(evidence_confidence / 100, 2),
        score=priority_score,
        priority=priority,
        priority_score=priority_score,
        likelihood_malicious=likelihood_malicious,
        potential_impact=potential_impact,
        evidence_confidence=evidence_confidence,
        rationale=rationale,
    )

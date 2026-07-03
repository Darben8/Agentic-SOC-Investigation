from __future__ import annotations

from typing import Any

from state import AttackMapping, ThreatIntelResult


def map_attack_techniques(
    alert_type: str,
    alert: dict[str, Any],
    intel_results: list[ThreatIntelResult],
) -> list[AttackMapping]:
    mappings: list[AttackMapping] = []

    if alert_type == "brute_force":
        mappings.append(
            AttackMapping(
                tactic="Credential Access",
                technique_id="T1110",
                technique_name="Brute Force",
                rationale="Repeated authentication failures or login attempts align with brute force behavior.",
            )
        )
    elif alert_type == "suspicious_url":
        mappings.append(
            AttackMapping(
                tactic="Initial Access",
                technique_id="T1566.002",
                technique_name="Phishing: Spearphishing Link",
                rationale="A suspicious URL can indicate user-targeted phishing or malicious redirection.",
            )
        )
    elif alert_type == "external_reconnaissance":
        mappings.append(
            AttackMapping(
                tactic="Reconnaissance",
                technique_id="T1595.001",
                technique_name="Active Scanning: Scanning IP Blocks",
                rationale="Multiple connection attempts across ports suggest active service discovery or scanning.",
            )
        )
        mappings.append(
            AttackMapping(
                tactic="Discovery",
                technique_id="T1046",
                technique_name="Network Service Scanning",
                rationale="Destination port enumeration is consistent with network service scanning.",
            )
        )
    else:
        mappings.append(
            AttackMapping(
                tactic="Unknown",
                technique_id="T1580",
                technique_name="Gather Victim Network Information",
                rationale="The alert is ambiguous, so the ATT&CK mapping is provisional.",
            )
        )

    if any(result.reputation == "malicious" for result in intel_results):
        mappings.append(
            AttackMapping(
                tactic="Command and Control",
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                rationale="Malicious indicator reputation may suggest adversary-controlled infrastructure involvement.",
            )
        )

    return mappings

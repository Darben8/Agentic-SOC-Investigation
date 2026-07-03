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
    elif alert_type == "powershell":
        mappings.append(
            AttackMapping(
                tactic="Execution",
                technique_id="T1059.001",
                technique_name="Command and Scripting Interpreter: PowerShell",
                rationale="The use of PowerShell is consistent with command execution techniques.",
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
                tactic="Infrastructure",
                technique_id="T1583",
                technique_name="Acquire Infrastructure",
                rationale="Malicious indicator reputation suggests possible adversary-controlled or abused infrastructure, but available evidence does not confirm command-and-control activity.",
            )
        )

    return mappings

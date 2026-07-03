from __future__ import annotations

from typing import Any

from state import InvestigationState
from tools.resolution_tools import extract_hostname, is_public_ip, resolve_dns
from tools.threat_intel_tools import enrich_indicators


def run_threat_intel(state: InvestigationState) -> dict[str, Any]:
    entities = state.entities
    indicators: list[tuple[str, str]] = []
    provenance_map: dict[tuple[str, str], dict[str, Any]] = {}
    resolution_trace: list[dict[str, Any]] = []
    fallback_notes: list[str] = list(state.fallback_notes)
    errors: list[str] = list(state.errors)

    def add_indicator(
        indicator: str,
        indicator_type: str,
        provenance: str,
        derived_from: str | None = None,
        cname: str | None = None,
    ) -> None:
        key = (indicator, indicator_type)
        if key not in provenance_map:
            indicators.append(key)
            provenance_map[key] = {
                "provenance": provenance,
                "derived_from": [] if derived_from is None else [derived_from],
                "cname": cname,
            }
            return

        existing = provenance_map[key]
        if existing["provenance"] != provenance and existing["provenance"] != "original":
            existing["provenance"] = provenance
        if derived_from and derived_from not in existing["derived_from"]:
            existing["derived_from"].append(derived_from)
        if cname and not existing.get("cname"):
            existing["cname"] = cname

    for ip in entities.ips:
        if is_public_ip(ip):
            add_indicator(ip, "ip", "original")
        else:
            note = f"Skipped enrichment for private/internal IP {ip}."
            if note not in fallback_notes:
                fallback_notes.append(note)

    for url in entities.urls:
        add_indicator(url, "url", "original")
        hostname = extract_hostname(url)
        if hostname:
            add_indicator(hostname, "domain", "derived_context", derived_from=url)
            resolution = resolve_dns(hostname)
            resolution_trace.append({"source_indicator": url, "resolution": resolution})
            primary_ip = resolution.get("primary_ip")
            if primary_ip and is_public_ip(primary_ip):
                add_indicator(
                    primary_ip,
                    "ip",
                    "derived_dns",
                    derived_from=hostname,
                    cname=resolution.get("cname"),
                )
            elif primary_ip and not is_public_ip(primary_ip):
                note = f"Resolved {hostname} to private/internal IP {primary_ip}; skipping IP enrichment."
                if note not in fallback_notes:
                    fallback_notes.append(note)
            elif resolution.get("error"):
                error = f"DNS resolution failed for {hostname}; proceeding with URL/domain enrichment only."
                if error not in errors:
                    errors.append(error)

    for domain in entities.domains:
        add_indicator(domain, "domain", "original")
        resolution = resolve_dns(domain)
        resolution_trace.append({"source_indicator": domain, "resolution": resolution})
        primary_ip = resolution.get("primary_ip")
        if primary_ip and is_public_ip(primary_ip):
            add_indicator(
                primary_ip,
                "ip",
                "derived_dns",
                derived_from=domain,
                cname=resolution.get("cname"),
            )
        elif primary_ip and not is_public_ip(primary_ip):
            note = f"Resolved {domain} to private/internal IP {primary_ip}; skipping IP enrichment."
            if note not in fallback_notes:
                fallback_notes.append(note)
        elif resolution.get("error"):
            error = f"DNS resolution failed for {domain}; proceeding with domain enrichment only."
            if error not in errors:
                errors.append(error)

    results = enrich_indicators(indicators)

    for result in results:
        metadata = provenance_map.get((result.indicator, result.indicator_type), {})
        result.details["provenance"] = metadata.get("provenance", "original")
        result.details["derived_from"] = metadata.get("derived_from", [])
        if metadata.get("cname"):
            result.details["cname"] = metadata["cname"]
        if getattr(result, "mocked", False):
            note = f"Used mock threat intelligence for {result.indicator} ({result.indicator_type})."
            if note not in fallback_notes:
                fallback_notes.append(note)
        for error in getattr(result, "errors", []):
            if error not in errors:
                errors.append(error)

    return {
        "threat_intel_results": results,
        "fallback_notes": fallback_notes,
        "errors": errors,
        "threat_intel_output": {
            "indicators_requested": indicators,
            "resolution_trace": resolution_trace,
            "fallback_notes": fallback_notes,
            "results": [result.model_dump() for result in results],
        },
    }

from __future__ import annotations

from typing import Any

from ingestion.input_router import route_input
from ingestion.splunk_loader import extract_splunk_events
from ingestion.ufw_parser import group_ufw_events


NORMALIZED_ALERT_KEYS = {
    "alert_name",
    "alert_type",
    "severity",
    "source",
}


def _looks_normalized(input_data: Any) -> bool:
    return isinstance(input_data, dict) and bool(NORMALIZED_ALERT_KEYS & set(input_data.keys()))


def _normalize_group(group: dict[str, Any]) -> dict[str, Any]:
    unique_ports = sorted(group["destination_ports"])
    is_scan = group["protocol"] == "TCP" and group["syn_count"] >= 3 and len(unique_ports) >= 3

    confidence_score = (
        group["event_count"] * 2
        + len(unique_ports) * 5
        + (10 if group["action"] == "blocked" else 0)
        + (15 if is_scan else 0)
    )

    alert_type = "network_reconnaissance" if is_scan else "unknown"
    alert_name = "Potential Port Scan Detected" if is_scan else "Normalized Splunk Security Event"
    summary = (
        "Multiple TCP SYN packets from one source IP to several destination ports were blocked by UFW."
        if is_scan
        else "Splunk firewall events were normalized, but the behavior did not strongly match a port scan pattern."
    )

    severity = "medium" if is_scan else "low"
    return {
        "alert_name": alert_name,
        "alert_type": alert_type,
        "severity": severity,
        "source": "Splunk",
        "sourcetype": group["sourcetype"] or "linux:ufw",
        "src_ip": group["src_ip"],
        "dst_ip": group["dst_ip"],
        "protocol": group["protocol"],
        "action": group["action"],
        "event_count": group["event_count"],
        "unique_destination_ports": len(unique_ports),
        "destination_ports": unique_ports,
        "raw_event_summary": summary,
        "raw_events_available": bool(group["raw_events"]),
        "time_window": group["time_bucket"],
        "normalization_confidence": confidence_score,
    }


def normalize_input(input_data: Any) -> dict:
    """Normalize supported inputs into a single alert object."""
    input_type, routed_input = route_input(input_data)
    if _looks_normalized(routed_input):
        normalized = dict(routed_input)
        normalized.setdefault("raw_input_type", input_type)
        normalized.setdefault("raw_input", input_data if isinstance(input_data, str) else str(input_data))
        normalized.setdefault("metadata", {})
        return normalized

    events = extract_splunk_events(routed_input)
    if not events:
        raise ValueError("No usable normalized alert fields or raw Splunk events were found in the input.")

    groups = group_ufw_events(events)
    if not groups:
        raise ValueError("Splunk events were found, but no parsable UFW-related records could be normalized.")

    normalized_alerts = [_normalize_group(group) for group in groups]
    normalized_alerts.sort(key=lambda item: item.get("normalization_confidence", 0), reverse=True)
    normalized = normalized_alerts[0]
    normalized["raw_input_type"] = input_type
    normalized["raw_input"] = routed_input
    normalized.setdefault("metadata", {})
    return normalized

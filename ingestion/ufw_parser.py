from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any


PAIR_PATTERN = re.compile(r"([A-Z_]+)=([^\s]+)")


def parse_ufw_event(event: dict[str, Any]) -> dict[str, Any]:
    raw_text = str(event.get("_raw", ""))
    parsed = dict(event)

    for key, value in PAIR_PATTERN.findall(raw_text):
        parsed.setdefault(key, value)

    upper_raw = raw_text.upper()
    if "UFW BLOCK" in upper_raw:
        parsed["ufw_action"] = "blocked"
    elif "UFW ALLOW" in upper_raw:
        parsed["ufw_action"] = "allowed"
    elif "UFW AUDIT" in upper_raw:
        parsed["ufw_action"] = "audit"

    parsed["syn_flag"] = "SYN" in upper_raw
    return parsed


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None

    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.utcfromtimestamp(float(value))
        except (TypeError, ValueError):
            return None


def group_ufw_events(events: list[dict[str, Any]], window_minutes: int = 5) -> list[dict[str, Any]]:
    parsed_events = [parse_ufw_event(event) for event in events]
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for event in parsed_events:
        src_ip = str(event.get("SRC") or event.get("src_ip") or "").strip()
        dst_ip = str(event.get("DST") or event.get("dst_ip") or "").strip()
        protocol = str(event.get("PROTO") or event.get("protocol") or "unknown").upper()
        event_time = _parse_time(event.get("_time"))
        if not src_ip and not dst_ip and not event.get("_raw"):
            continue

        if event_time:
            bucket_start = event_time - timedelta(
                minutes=event_time.minute % window_minutes,
                seconds=event_time.second,
                microseconds=event_time.microsecond,
            )
            bucket = bucket_start.isoformat()
        else:
            bucket = "unknown_time_bucket"

        key = (src_ip, dst_ip, protocol, bucket)
        if key not in grouped:
            grouped[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "time_bucket": bucket,
                "source": str(event.get("source", "")),
                "host": str(event.get("host", "")),
                "sourcetype": str(event.get("sourcetype", "")),
                "action": str(event.get("ufw_action") or event.get("action") or "unknown"),
                "event_count": 0,
                "destination_ports": set(),
                "raw_events": [],
                "syn_count": 0,
            }

        group = grouped[key]
        dpt = event.get("DPT") or event.get("dest_port") or event.get("dpt")
        if dpt:
            group["destination_ports"].add(str(dpt))
        group["event_count"] += 1
        group["raw_events"].append(event)
        if event.get("syn_flag"):
            group["syn_count"] += 1

    return list(grouped.values())

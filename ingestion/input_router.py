from __future__ import annotations

from typing import Any

from ingestion.observation_normalizer import normalize_observation_input
from ingestion.splunk_loader import extract_splunk_events
from ingestion.url_normalizer import normalize_url_input


def detect_input_type(input_data: Any) -> str:
    if isinstance(input_data, dict):
        explicit_type = str(input_data.get("input_type", "")).lower()
        if explicit_type in {"normalized_alert", "raw_log_export", "suspicious_url", "manual_observation"}:
            return explicit_type
        if "url" in input_data and not {"alert_name", "alert_type", "source"} & set(input_data.keys()):
            return "suspicious_url"
        if "observation" in input_data and not {"alert_name", "alert_type"} & set(input_data.keys()):
            return "manual_observation"
        if {"alert_name", "alert_type", "severity", "source"} & set(input_data.keys()):
            return "normalized_alert"
        if extract_splunk_events(input_data):
            return "raw_log_export"
    elif isinstance(input_data, list):
        if extract_splunk_events(input_data):
            return "raw_log_export"
    elif isinstance(input_data, str):
        stripped = input_data.strip()
        if stripped.startswith(("http://", "https://")) or "." in stripped and " " not in stripped:
            return "suspicious_url"
        return "manual_observation"

    return "unknown"


def route_input(input_data: Any) -> tuple[str, Any]:
    input_type = detect_input_type(input_data)

    if input_type == "suspicious_url":
        if isinstance(input_data, dict):
            value = input_data.get("value") or input_data.get("url") or ""
        else:
            value = str(input_data)
        return input_type, normalize_url_input(str(value))

    if input_type == "manual_observation":
        if isinstance(input_data, dict):
            value = input_data.get("value") or input_data.get("observation") or ""
        else:
            value = str(input_data)
        return input_type, normalize_observation_input(str(value))

    return input_type, input_data

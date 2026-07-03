from __future__ import annotations

from urllib.parse import urlparse


def normalize_url_input(url: str) -> dict:
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("A suspicious URL input was selected, but no URL was provided.")

    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"

    parsed = urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError("The suspicious URL input could not be parsed into a valid URL.")

    return {
        "alert_name": "Suspicious URL Submitted",
        "alert_type": "suspicious_url",
        "source": "Manual URL Input",
        "severity": "medium",
        "timestamp": "",
        "src_ip": None,
        "dst_ip": None,
        "url": cleaned,
        "domain": parsed.hostname,
        "username": None,
        "host": None,
        "protocol": parsed.scheme.upper(),
        "destination_ports": [],
        "event_count": 1,
        "raw_input_type": "suspicious_url",
        "raw_input": url,
        "raw_event_summary": "A user submitted a suspicious URL directly for investigation.",
        "metadata": {"path": parsed.path or "/", "query": parsed.query},
    }

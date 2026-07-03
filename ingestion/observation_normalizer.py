from __future__ import annotations

from tools.ioc_extractor import extract_entities


def normalize_observation_input(observation: str) -> dict:
    cleaned = observation.strip()
    if not cleaned:
        raise ValueError("A manual observation input was selected, but no observation text was provided.")

    entities = extract_entities({"observation": cleaned})

    return {
        "alert_name": "Manual Analyst Observation",
        "alert_type": "unknown",
        "source": "Manual Observation",
        "severity": "low",
        "timestamp": "",
        "src_ip": entities.ips[0] if entities.ips else None,
        "dst_ip": entities.ips[1] if len(entities.ips) > 1 else None,
        "url": entities.urls[0] if entities.urls else None,
        "domain": entities.domains[0] if entities.domains else None,
        "username": entities.users[0] if entities.users else None,
        "host": entities.hosts[0] if entities.hosts else None,
        "protocol": None,
        "destination_ports": entities.ports,
        "event_count": 1,
        "raw_input_type": "manual_observation",
        "raw_input": observation,
        "raw_event_summary": cleaned,
        "metadata": {
            "entities_preview": entities.model_dump(),
        },
    }

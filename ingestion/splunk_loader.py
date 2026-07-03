from __future__ import annotations

from typing import Any


def extract_splunk_events(input_data: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    """Extract a flat event list from several common Splunk export shapes."""
    if isinstance(input_data, list):
        return [item for item in input_data if isinstance(item, dict)]

    if not isinstance(input_data, dict):
        return []

    for key in ["events", "results", "records"]:
        value = input_data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    result_block = input_data.get("result")
    if isinstance(result_block, dict):
        for key in ["events", "results", "records"]:
            value = result_block.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    if {"_raw", "_time"} & set(input_data.keys()):
        return [input_data]

    return []

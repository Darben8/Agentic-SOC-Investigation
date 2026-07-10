from __future__ import annotations

from typing import Any


MAX_TEXT_LENGTH = 10000
MAX_LIST_ITEMS = 5000


def _sanitize_text(value: str) -> str:
    return value.replace("\x00", "").strip()


def validate_and_sanitize_input(input_data: Any) -> tuple[Any, list[dict[str, Any]], list[str]]:
    """Validate and sanitize user input before routing or normalization."""
    validation_results: list[dict[str, Any]] = []
    errors: list[str] = []

    if input_data is None:
        raise ValueError("Input cannot be empty.")

    if isinstance(input_data, str):
        sanitized = _sanitize_text(input_data)
        validation_results.append(
            {
                "stage": "pre_router_validation",
                "check": "string_input",
                "status": "passed" if sanitized else "failed",
                "details": "Input string sanitized and checked for emptiness.",
            }
        )
        if not sanitized:
            raise ValueError("Input text is empty after sanitization.")
        if len(sanitized) > MAX_TEXT_LENGTH:
            raise ValueError(f"Input text exceeds the maximum supported length of {MAX_TEXT_LENGTH} characters.")
        return sanitized, validation_results, errors

    if isinstance(input_data, list):
        validation_results.append(
            {
                "stage": "pre_router_validation",
                "check": "list_input",
                "status": "passed" if len(input_data) <= MAX_LIST_ITEMS else "failed",
                "details": f"List input contains {len(input_data)} item(s).",
            }
        )
        if len(input_data) > MAX_LIST_ITEMS:
            raise ValueError(f"Input list exceeds the maximum supported size of {MAX_LIST_ITEMS} items.")
        if not all(isinstance(item, (dict, str, int, float, bool, list, type(None))) for item in input_data):
            errors.append("Input list contains unsupported item types; some values may not be processed correctly.")
        return input_data, validation_results, errors

    if isinstance(input_data, dict):
        sanitized = dict(input_data)
        if "value" in sanitized and isinstance(sanitized["value"], str):
            sanitized["value"] = _sanitize_text(sanitized["value"])
        if "url" in sanitized and isinstance(sanitized["url"], str):
            sanitized["url"] = _sanitize_text(sanitized["url"])
        if "observation" in sanitized and isinstance(sanitized["observation"], str):
            sanitized["observation"] = _sanitize_text(sanitized["observation"])

        validation_results.append(
            {
                "stage": "pre_router_validation",
                "check": "dict_input",
                "status": "passed",
                "details": f"Dictionary input with keys: {sorted(sanitized.keys())}",
            }
        )
        return sanitized, validation_results, errors

    raise ValueError(f"Unsupported input type for validation: {type(input_data).__name__}")

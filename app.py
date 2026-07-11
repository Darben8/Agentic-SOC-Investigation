from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from graph import run_soc_investigation
from ingestion.alert_normalizer import normalize_input

SAMPLE_DIR = Path("data/sample_alerts")


def load_sample_files() -> dict[str, str]:
    samples: dict[str, str] = {}
    if SAMPLE_DIR.exists():
        for file_path in sorted(SAMPLE_DIR.glob("*.json")):
            samples[file_path.name] = file_path.read_text(encoding="utf-8")
    return samples


def sample_names_for_mode(samples: dict[str, str], input_mode: str) -> list[str]:
    mode_map = {
        "Normalized Alert JSON": {"bruteforce.json", "port_scan.json", "suspicious_url.json"},
        "Raw Log Export": {"raw_splunk_ufw.json"},
        "Suspicious URL": {"url_input.json"},
        "Manual Observation": {"manual_observation.json"},
    }
    return ["None"] + sorted(name for name in samples if name in mode_map.get(input_mode, set()))


def parse_json_input(raw_text: str) -> dict | list:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}.") from exc


def main() -> None:
    st.set_page_config(page_title="SOC Investigation Copilot", layout="wide")
    st.title("LangGraph SOC Investigation Copilot")
    st.write("Choose an input mode and run the sequential SOC investigation workflow.")

    samples = load_sample_files()
    input_mode = st.radio(
        "Input mode",
        [
            "Normalized Alert JSON",
            "Raw Log Export",
            "Suspicious URL",
            "Manual Observation",
        ],
    )

    if input_mode in {"Normalized Alert JSON", "Raw Log Export"}:
        selected_sample = st.selectbox("Choose a sample input", sample_names_for_mode(samples, input_mode))
        uploaded_file = st.file_uploader("Upload a JSON file", type=["json"])
        default_text = samples.get(selected_sample, "") if selected_sample != "None" else ""
        raw_input_text = st.text_area(
            "Paste JSON input",
            value=default_text,
            height=300,
        )
        if uploaded_file is not None:
            raw_input_text = uploaded_file.getvalue().decode("utf-8")
    elif input_mode == "Suspicious URL":
        selected_sample = st.selectbox("Choose a sample input", sample_names_for_mode(samples, input_mode))
        raw_input_text = st.text_input(
            "Enter a suspicious URL",
            value=(
                parse_json_input(samples[selected_sample])["value"]
                if selected_sample != "None"
                else "http://rnicrosoft-support.human-resources.services"
            ),
        )
    else:
        selected_sample = st.selectbox("Choose a sample input", sample_names_for_mode(samples, input_mode))
        raw_input_text = st.text_area(
            "Enter a manual analyst observation",
            value=(
                parse_json_input(samples[selected_sample])["value"]
                if selected_sample != "None"
                else "Multiple connections across ports from 192.168.56.40 to 192.168.56.11 were blocked by UFW."
            ),
            height=180,
        )

    run_clicked = st.button("Run Investigation", type="primary")

    if not run_clicked:
        return

    if not raw_input_text.strip():
        st.error("Please provide an input for the selected mode.")
        return

    try:
        if input_mode == "Normalized Alert JSON":
            parsed_input = parse_json_input(raw_input_text)
            workflow_input: Any = parsed_input
        elif input_mode == "Raw Log Export":
            parsed_input = parse_json_input(raw_input_text)
            workflow_input = parsed_input
        elif input_mode == "Suspicious URL":
            parsed_input = {"input_type": "suspicious_url", "value": raw_input_text}
            workflow_input = parsed_input
        else:
            parsed_input = {"input_type": "manual_observation", "value": raw_input_text}
            workflow_input = parsed_input

        normalized_alert = normalize_input(workflow_input)
        result = run_soc_investigation(workflow_input)
    except ValueError as exc:
        st.error(str(exc))
        return
    except Exception as exc:
        st.error(f"The investigation workflow failed: {exc}")
        return

    st.subheader("Final Investigation Report")
    st.json(
        result.final_report.model_dump() if hasattr(result.final_report, "model_dump") else result.final_report,
        expanded=True,
    )

    sections = [
        ("Raw Input", result.raw_input),
        ("Normalized Alert", result.normalized_alert),
        ("Planner Output", result.planner_output),
        (
            "Threat Intelligence Output",
            result.threat_intel_output
            or [item.model_dump() if hasattr(item, "model_dump") else item for item in result.threat_intel_results],
        ),
        ("Investigation Output", result.investigation_output),
        (
            "Critic Output",
            result.critic_feedback.model_dump() if hasattr(result.critic_feedback, "model_dump") else result.critic_feedback,
        ),
        ("Fallback Notes", result.fallback_notes),
        ("Errors", result.errors),
        ("Policy Violations", result.policy_violations),
        (
            "Revision Loop Results",
            {
                "needs_revision": result.needs_revision,
                "revision_count": result.revision_count,
                "revision_history": result.revision_history,
            },
        ),
        ("Source Attribution", result.source_attribution),
        ("Validation Results", result.validation_results),
        ("Audit Log", result.audit_log),
    ]

    for title, payload in sections:
        with st.expander(title, expanded=False):
            st.json(payload, expanded=False)


if __name__ == "__main__":
    main()

from __future__ import annotations

import html
import json
import re
import time
from pathlib import Path
from typing import Any

import streamlit as st

from graph import run_soc_investigation
from ingestion.alert_normalizer import normalize_input
from tools.attack_mapper import map_attack_techniques
from tools.risk_score import score_risk

SAMPLE_DIR = Path("data/sample_alerts")


def load_sample_files() -> dict[str, str]:
    samples: dict[str, str] = {}
    if SAMPLE_DIR.exists():
        for file_path in sorted(SAMPLE_DIR.glob("*.json")):
            samples[file_path.name] = file_path.read_text(encoding="utf-8")
    return samples


def sample_names_for_mode(samples: dict[str, str], input_mode: str) -> list[str]:
    # Keep the selector simple for demos: every sample file is available in every mode.
    return ["None"] + sorted(samples)


def sample_value_for_mode(sample_text: str, input_mode: str) -> str:
    if input_mode in {"Normalized Alert JSON", "Raw Log Export"}:
        return sample_text

    try:
        sample_data = parse_json_input(sample_text)
    except ValueError:
        return sample_text

    if isinstance(sample_data, dict):
        for key in ("value", "url", "input", "raw_input", "observation"):
            if key in sample_data and isinstance(sample_data[key], str):
                return sample_data[key]
    return sample_text


def parse_json_input(raw_text: str) -> dict | list:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}.") from exc


def format_status(stop_reason: str) -> str:
    mapping = {
        "investigation_complete": "Investigation complete",
        "investigation_complete_with_limitations": "Complete with limitations",
        "benign_allowlisted": "Closed as benign",
        "malformed_or_incomplete_input": "Needs better input",
        "adversarial_input_detected": "Adversarial input blocked",
        "insufficient_evidence": "Insufficient evidence",
    }
    return mapping.get(stop_reason, "In review")


def format_classification(alert_type: str) -> str:
    if not alert_type:
        return "Unknown"
    return alert_type.replace("_", " ").title()


def clean_markdown_text(value: Any) -> str:
    text = str(value or "").replace("\\n", "\n")
    text = text.replace("[date]", "").replace("(date)", "")
    text = re.sub(r"(?im)^\s*#{1,6}\s*", "", text)
    text = re.sub(r"(?im)^\s*(SOC Investigation Summary:?|Alert Overview:?|Incident Overview:?|Details:?|Event Summary:)\s*$", "", text)
    text = re.sub(r"(?im)^\s*[-*•]\s+", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def extract_summary_facts_and_prose(summary_text: str) -> tuple[list[tuple[str, str]], str]:
    label_map = {
        "Alert Name": "Alert",
        "Alert Type": "Type",
        "Severity": "Severity",
        "Source": "Source",
        "Source Type": "Source Type",
        "Action Taken": "Action",
        "Source IP": "Source IP",
        "Destination IP": "Destination IP",
        "Protocol": "Protocol",
        "Action": "Action",
        "Event Count": "Event Count",
        "Unique Destination Ports": "Unique Ports",
        "Destination Ports Involved": "Ports",
    }
    facts: list[tuple[str, str]] = []
    prose_lines: list[str] = []

    for raw_line in summary_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        fact_match = re.match(
            r"^(?:[-*•]\s+)?(?P<label>Alert Name|Alert Type|Severity|Source|Source Type|Action Taken|Source IP|Destination IP|Protocol|Action|Event Count|Unique Destination Ports|Destination Ports Involved)\s*:\s*(?P<value>.+)$",
            line,
            flags=re.IGNORECASE,
        )
        if fact_match:
            raw_label = fact_match.group("label").strip()
            value = fact_match.group("value").strip(" \n\r\t-:;,")
            normalized_label = next((label_map[key] for key in label_map if key.lower() == raw_label.lower()), raw_label)
            facts.append((normalized_label, value))
        else:
            prose_lines.append(raw_line)

    prose = "\n".join(prose_lines)
    prose = re.sub(r"(?im)\b(SOC Investigation Summary|Alert Overview|Incident Overview|Details|Event Summary)\b\s*:?", "", prose)
    prose = re.sub(r"\n{3,}", "\n\n", prose).strip(" \n\r\t:;-")

    unique_facts: list[tuple[str, str]] = []
    seen_labels: set[str] = set()
    for label, value in facts:
        if label in seen_labels:
            continue
        seen_labels.add(label)
        unique_facts.append((label, value))

    return unique_facts, prose


def format_title(final_report: dict[str, Any], normalized_alert: dict[str, Any], raw_input_type: str) -> str:
    title = final_report.get("title") or normalized_alert.get("alert_name") or "Investigation Report"
    primary_indicator = (
        normalized_alert.get("src_ip")
        or normalized_alert.get("url")
        or normalized_alert.get("domain")
        or normalized_alert.get("username")
        or ""
    )
    if primary_indicator:
        return f"{title} - {primary_indicator}"
    if raw_input_type:
        return f"{title} - {raw_input_type.replace('_', ' ')}"
    return str(title)


def format_attack_rows(attack_mapping: list[Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in attack_mapping:
        if hasattr(item, "model_dump"):
            payload = item.model_dump()
        else:
            payload = item
        rows.append(
            {
                "Technique": f"{payload.get('technique_id', '')} - {payload.get('technique_name', '')}".strip(" -"),
                "Tactic": str(payload.get("tactic", "")),
            }
        )
    return rows


def summarize_source_attribution(items: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for item in items[:8]:
        source_type = item.get("source_type", "source").replace("_", " ").title()
        if item.get("indicator"):
            lines.append(f"{source_type}: {item['indicator']} ({item.get('indicator_type', 'unknown')})")
        elif item.get("technique_id"):
            lines.append(f"{source_type}: {item['technique_id']} {item.get('technique_name', '')}".strip())
        elif item.get("source_name"):
            lines.append(f"{source_type}: {item['source_name']} - {item.get('description', '')}".strip(" -"))
        elif item.get("source"):
            lines.append(f"{source_type}: {item['source']}")
    return lines


def summarize_validation(items: list[dict[str, Any]]) -> list[str]:
    return [
        f"{item.get('check', 'check').replace('_', ' ').title()}: {item.get('status', 'unknown')}"
        for item in items[:8]
    ]


def summarize_audit_log(items: list[dict[str, Any]]) -> list[str]:
    return [
        f"{item.get('agent_name', item.get('agent_id', 'Agent'))}: {item.get('action', 'action').replace('_', ' ')}"
        for item in items[:8]
    ]


def inject_app_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --soc-blue: #2f7df6;
            --soc-blue-soft: #eaf3ff;
            --soc-blue-border: #90b9ff;
            --soc-border: #d9e0ea;
            --soc-text: #1f2937;
            --soc-muted: #6b7280;
            --soc-low-bg: #e8f7ee;
            --soc-low-fg: #177245;
            --soc-medium-bg: #fff3da;
            --soc-medium-fg: #9a6400;
            --soc-high-bg: #fde2e2;
            --soc-high-fg: #a12622;
            --soc-critical-bg: #f8d4d4;
            --soc-critical-fg: #7f1d1d;
        }

        .block-container {
            max-width: 1050px;
            margin: 0 auto;
            padding-top: 1.5rem;
            padding-bottom: 1.5rem;
        }

        .stButton button[kind="primary"] {
            background: var(--soc-blue) !important;
            border-color: var(--soc-blue) !important;
            color: white !important;
        }

        .stButton button[kind="primary"]:hover {
            background: #1f6ae0 !important;
            border-color: #1f6ae0 !important;
        }

        [data-testid="stFileUploaderDropzone"] {
            border: 1.5px dashed var(--soc-border) !important;
            border-radius: 12px !important;
            background: #fbfcfe !important;
            padding: 1rem !important;
        }

        [data-testid="stFileUploaderDropzone"] * {
            color: var(--soc-muted) !important;
        }

        div[data-testid="stRadio"][aria-label="View mode"] label {
            border: none;
            background: transparent;
            min-height: auto;
            padding: 0;
            border-radius: 0;
            justify-content: flex-start;
            box-shadow: none;
        }

        div[data-testid="stRadio"][aria-label="View mode"] label:hover {
            border: none;
            background: transparent;
        }

        div[data-testid="stRadio"][aria-label="View mode"] label > div:first-child {
            display: flex;
        }

        div[data-testid="stRadio"][aria-label="View mode"] label p {
            text-align: left;
            font-weight: 500;
            line-height: 1.2;
        }

        div[data-testid="stRadio"][aria-label="View mode"] label:has(input:checked) {
            border: none;
            background: transparent;
            box-shadow: none;
        }

        .report-card {
            border: 1px solid var(--soc-border);
            border-radius: 16px;
            padding: 1.25rem 1.25rem 1rem;
            background: white;
            margin-bottom: 1rem;
        }

        .report-kicker {
            color: var(--soc-muted);
            font-size: 0.92rem;
            margin-bottom: 0.2rem;
        }

        .report-title-row {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .report-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--soc-text);
            line-height: 1.1;
            margin: 0;
        }

        .severity-badge {
            display: inline-block;
            border-radius: 999px;
            padding: 0.3rem 0.8rem;
            font-size: 0.8rem;
            font-weight: 600;
            white-space: nowrap;
        }

        .severity-low { background: var(--soc-low-bg); color: var(--soc-low-fg); }
        .severity-medium { background: var(--soc-medium-bg); color: var(--soc-medium-fg); }
        .severity-high { background: var(--soc-high-bg); color: var(--soc-high-fg); }
        .severity-critical { background: var(--soc-critical-bg); color: var(--soc-critical-fg); }
        .severity-unknown { background: #eef2f7; color: #475569; }

        .metric-card {
            border: 1px solid #edf1f5;
            border-radius: 14px;
            background: #fbfcfe;
            padding: 1rem;
            min-height: 94px;
        }

        .metric-label {
            color: var(--soc-muted);
            font-size: 0.9rem;
            margin-bottom: 0.35rem;
        }

        .metric-value {
            color: var(--soc-text);
            font-size: 1.2rem;
            font-weight: 700;
            line-height: 1.00;
        }

        .metric-value.small {
            font-size: 1.0rem;
        }

        .metric-badge-wrap {
            margin-top: 0.2rem;
        }

        .st-key-input_mode_normalized button,
        .st-key-input_mode_raw_log button,
        .st-key-input_mode_url button,
        .st-key-input_mode_observation button {
            min-height: 88px;
            border-radius: 14px;
            border: 1px solid var(--soc-border);
            background: white;
            color: var(--soc-text);
            font-weight: 600;
            white-space: pre-line;
        }

        .st-key-input_mode_normalized button:hover,
        .st-key-input_mode_raw_log button:hover,
        .st-key-input_mode_url button:hover,
        .st-key-input_mode_observation button:hover {
            border-color: var(--soc-blue-border);
            color: var(--soc-text);
        }

        .st-key-input_mode_normalized button[kind="primary"],
        .st-key-input_mode_raw_log button[kind="primary"],
        .st-key-input_mode_url button[kind="primary"],
        .st-key-input_mode_observation button[kind="primary"] {
            background: var(--soc-blue-soft) !important;
            color: #1357b8 !important;
            border: 2px solid var(--soc-blue) !important;
            box-shadow: inset 0 0 0 1px rgba(47, 125, 246, 0.05);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def severity_class(severity: str) -> str:
    value = str(severity or "unknown").lower()
    return value if value in {"low", "medium", "high", "critical"} else "unknown"


def render_severity_badge(severity: str) -> str:
    normalized = severity_class(severity)
    return f"<span class='severity-badge severity-{normalized}'>{normalized.title()} severity</span>"


def render_priority_badge(priority: str) -> str:
    normalized = severity_class(priority)
    return f"<span class='severity-badge severity-{normalized}'>{normalized.title()} priority</span>"


def render_metric_card(label: str, value: str, *, small: bool = False, badge_html: str | None = None) -> None:
    value_class = "metric-value small" if small else "metric-value"
    badge_block = f"<div class='metric-badge-wrap'>{badge_html}</div>" if badge_html else ""
    safe_label = html.escape(str(label))
    safe_value = html.escape(str(value))
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{safe_label}</div>
            <div class="{value_class}">{safe_value}</div>
            {badge_block}
        </div>
        """,
        unsafe_allow_html=True,
    )


def resolve_risk_score(result: Any, final_report: dict[str, Any]) -> int | None:
    investigation_risk = result.investigation_output.get("risk", {})
    score = investigation_risk.get("score")
    if isinstance(score, int):
        return score

    for item in final_report.get("source_attribution", []):
        if item.get("source_type") == "risk_score" and isinstance(item.get("score"), int):
            return item["score"]

    if result.alert_type == "prompt_injection":
        attack_mapping = map_attack_techniques(result.alert_type, result.normalized_alert or result.raw_alert, [])
        return score_risk(result.alert_type, result.normalized_alert or result.raw_alert, [], attack_mapping).score

    return None


def resolve_risk_payload(result: Any, final_report: dict[str, Any]) -> dict[str, Any]:
    investigation_risk = result.investigation_output.get("risk", {})
    if investigation_risk:
        return investigation_risk

    for item in final_report.get("source_attribution", []):
        if item.get("source_type") == "risk_score":
            return item

    if result.alert_type == "prompt_injection":
        attack_mapping = map_attack_techniques(result.alert_type, result.normalized_alert or result.raw_alert, [])
        return score_risk(result.alert_type, result.normalized_alert or result.raw_alert, [], attack_mapping).model_dump()

    return {}


def append_status_step(message: str) -> None:
    steps = list(st.session_state.get("status_steps", []))
    steps.append(message)
    st.session_state["status_steps"] = steps


def render_persistent_status() -> None:
    label = st.session_state.get("status_label")
    state = st.session_state.get("status_state", "complete")
    steps = st.session_state.get("status_steps", [])
    if not label:
        return
    with st.status(label, state=state, expanded=(state != "complete")):
        for step in steps:
            st.write(step)


def main() -> None:
    st.set_page_config(page_title="SOC Investigation Copilot", layout="wide")
    inject_app_css()
    st.title("SOC Investigation Copilot")
    st.write("Choose an input mode and run the sequential SOC investigation workflow.")

    if "investigation_running" not in st.session_state:
        st.session_state["investigation_running"] = False
    if "run_requested" not in st.session_state:
        st.session_state["run_requested"] = False

    view_mode = st.radio(
        "View mode",
        ["Analyst View", "Developer / Audit View"],
        horizontal=True,
        help="Analyst View focuses on the investigation outcome. Developer / Audit View exposes the full workflow trace.",
    )

    samples = load_sample_files()
    mode_options = [
        "Normalized Alert JSON",
        "Raw Log Export",
        "Suspicious URL",
        "Manual Observation",
    ]
    mode_labels = {
        "Normalized Alert JSON": "📄\nNormalized alert",
        "Raw Log Export": "🗂️\nRaw log export",
        "Suspicious URL": "🔗\nSuspicious URL",
        "Manual Observation": "📝\nManual observation",
    }
    mode_keys = {
        "Normalized Alert JSON": "input_mode_normalized",
        "Raw Log Export": "input_mode_raw_log",
        "Suspicious URL": "input_mode_url",
        "Manual Observation": "input_mode_observation",
    }
    if "selected_input_mode" not in st.session_state:
        st.session_state["selected_input_mode"] = "Normalized Alert JSON"

    with st.container(border=True):
        st.markdown("**Input mode**")
        mode_columns = st.columns(len(mode_options))
        for column, option in zip(mode_columns, mode_options):
            with column:
                if st.button(
                    mode_labels[option],
                    key=mode_keys[option],
                    type="primary" if st.session_state["selected_input_mode"] == option else "secondary",
                    use_container_width=True,
                ):
                    st.session_state["selected_input_mode"] = option
        input_mode = st.session_state["selected_input_mode"]

        selected_sample = st.selectbox("Sample input", sample_names_for_mode(samples, input_mode))
        default_text = samples.get(selected_sample, "") if selected_sample != "None" else ""

        uploaded_file = None
        if input_mode in {"Normalized Alert JSON", "Raw Log Export"}:
            uploaded_file = st.file_uploader(
                "Upload a JSON file",
                type=["json"],
                help="Drag a file here, or click to browse. JSON only.",
            )

        if input_mode in {"Normalized Alert JSON", "Raw Log Export"}:
            raw_input_text = st.text_area(
                "Paste JSON input",
                value=default_text,
                height=260,
            )
            if uploaded_file is not None:
                raw_input_text = uploaded_file.getvalue().decode("utf-8")
        elif input_mode == "Suspicious URL":
            raw_input_text = st.text_input(
                "Suspicious URL",
                value=(
                    sample_value_for_mode(samples[selected_sample], input_mode)
                    if selected_sample != "None"
                    else "http://rnicrosoft-support.human-resources.services"
                ),
            )
        else:
            raw_input_text = st.text_area(
                "Manual observation",
                value=(
                    sample_value_for_mode(samples[selected_sample], input_mode)
                    if selected_sample != "None"
                    else "Multiple connections across ports from 192.168.56.40 to 192.168.56.11 were blocked by UFW."
                ),
                height=180,
            )

        run_clicked = st.button(
            "Investigation in progress..." if st.session_state["investigation_running"] else "Run Investigation",
            type="primary",
            disabled=st.session_state["investigation_running"],
        )

    if run_clicked:
        st.session_state["run_requested"] = True
        st.session_state["investigation_running"] = True
        st.session_state["status_label"] = "The Agentic SOC Copilot is working on your request."
        st.session_state["status_state"] = "running"
        st.session_state["status_steps"] = []
        st.rerun()

    render_persistent_status()

    stored_result = st.session_state.get("last_result")
    stored_mode = st.session_state.get("last_input_mode")
    stored_raw_text = st.session_state.get("last_raw_input_text")
    stored_runtime = st.session_state.get("last_runtime_seconds")
    result = None

    if st.session_state.get("run_requested"):
        if not raw_input_text.strip():
            st.session_state["investigation_running"] = False
            st.session_state["run_requested"] = False
            st.session_state["status_label"] = None
            st.session_state["status_steps"] = []
            st.error("Please provide an input for the selected mode.")
            return

        try:
            started = time.perf_counter()
            with st.status("The Agentic SOC Copilot is working on your request.", state="running", expanded=True) as status:
                append_status_step("Validating the selected input and preparing the workflow.")
                status.write(st.session_state["status_steps"][-1])

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

                append_status_step("Running the agentic SOC workflow and collecting evidence.")
                status.write(st.session_state["status_steps"][-1])
                result = run_soc_investigation(workflow_input)

                append_status_step("Compiling the investigation report and final risk assessment.")
                status.write(st.session_state["status_steps"][-1])

                runtime_seconds = round(time.perf_counter() - started, 2)
                completion_message = f"Investigation completed in {runtime_seconds:.2f} seconds."
                append_status_step(completion_message)
                status.write(completion_message)
                status.update(label="The Agentic SOC Copilot has completed your request.", state="complete", expanded=False)

            st.session_state["last_result"] = result
            st.session_state["last_input_mode"] = input_mode
            st.session_state["last_raw_input_text"] = raw_input_text
            st.session_state["last_runtime_seconds"] = runtime_seconds
            st.session_state["status_label"] = "The Agentic SOC Copilot has completed your request."
            st.session_state["status_state"] = "complete"
            st.session_state["investigation_running"] = False
            st.session_state["run_requested"] = False
            st.rerun()
        except ValueError as exc:
            st.session_state["investigation_running"] = False
            st.session_state["run_requested"] = False
            st.session_state["status_label"] = None
            st.session_state["status_steps"] = []
            st.error(str(exc))
            return
        except Exception as exc:
            st.session_state["investigation_running"] = False
            st.session_state["run_requested"] = False
            st.session_state["status_label"] = "The Agentic SOC Copilot could not complete your request."
            st.session_state["status_state"] = "error"
            append_status_step(f"Workflow failed: {exc}")
            st.error(f"The investigation workflow failed: {exc}")
            return
    elif stored_result is not None and stored_mode == input_mode and stored_raw_text == raw_input_text:
        result = stored_result
    else:
        return

    st.subheader("Final Investigation Report")
    top_cols = st.columns(3)
    top_cols[0].metric("Classified As", format_classification(result.alert_type))
    top_cols[1].metric("Status", format_status(result.stop_reason))
    top_cols[2].metric("Review Passes", result.revision_count + 1 if result.revision_count >= 0 else 1)

    final_report = result.final_report.model_dump() if hasattr(result.final_report, "model_dump") else result.final_report
    severity = final_report.get("severity", result.severity or "unknown")
    confidence = final_report.get("confidence", result.confidence or 0.0)
    recommended_actions = final_report.get("recommended_actions", [])
    caveats = final_report.get("caveats", [])
    evidence = final_report.get("evidence", [])
    attack_rows = format_attack_rows(final_report.get("attack_mapping", []))
    risk_payload = resolve_risk_payload(result, final_report)
    risk_score = resolve_risk_score(result, final_report)
    priority = risk_payload.get("priority", severity)
    runtime_seconds = stored_runtime
    display_title = format_title(final_report, result.normalized_alert, result.raw_input_type)

    if view_mode == "Analyst View":
        st.markdown(
            f"""
            <div class="report-card">
                <div class="report-kicker">Investigation report</div>
                <div class="report-title-row">
                    <h2 class="report-title">{display_title}</h2>
                    <div style="display:flex; gap:0.5rem; flex-wrap:wrap; justify-content:flex-end;">
                        {render_priority_badge(str(priority))}
                        {render_severity_badge(str(severity))}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        summary_cols = st.columns(5)
        confidence_value = f"{round(float(confidence) * 100)}%" if isinstance(confidence, (int, float)) else str(confidence)
        with summary_cols[0]:
            render_metric_card("Confidence", confidence_value)
        with summary_cols[1]:
            render_metric_card("Risk score", f"{risk_score} / 100" if risk_score is not None else "Not scored")
        with summary_cols[2]:
            #render_metric_card("Priority", str(priority).title(), small=True, badge_html=render_priority_badge(str(priority)))
            render_metric_card("Priority", str(priority).title(), small=True)
        with summary_cols[3]:
            render_metric_card("Status", format_status(result.stop_reason).replace("Investigation ", "").capitalize(), small=True)
        with summary_cols[4]:
            #render_metric_card("Severity", str(severity).title(), small=True, badge_html=render_severity_badge(str(severity)))
            render_metric_card("Severity", str(severity).title(), small=True)

        st.markdown("### Summary")
        summary_text = clean_markdown_text(final_report.get("executive_summary", ""))
        summary_facts, summary_prose = extract_summary_facts_and_prose(summary_text)
        if summary_facts:
            fact_columns = st.columns(min(4, len(summary_facts)))
            for index, (label, value) in enumerate(summary_facts[:4]):
                with fact_columns[index]:
                    render_metric_card(label, value, small=True)
            if len(summary_facts) > 4:
                extra_fact_columns = st.columns(min(4, len(summary_facts) - 4))
                for index, (label, value) in enumerate(summary_facts[4:8]):
                    with extra_fact_columns[index]:
                        render_metric_card(label, value, small=True)
        if summary_prose:
            st.markdown(summary_prose)
        elif summary_text:
            st.markdown(summary_text)
        else:
            st.write("No summary was generated.")
        if isinstance(runtime_seconds, (int, float)):
            st.caption(f"Investigation completed in {float(runtime_seconds):.2f} seconds.")

        if recommended_actions:
            st.markdown("### Recommended actions")
            for action in recommended_actions:
                st.write(f"- {action}")

        if attack_rows:
            st.markdown("### ATT&CK mapping")
            st.table(attack_rows)

        with st.expander("Advanced - agent and pipeline detail", expanded=False):
            advanced_sections = [
                ("Source attribution", summarize_source_attribution(result.source_attribution)),
                ("Fallback notes", [str(item) for item in result.fallback_notes]),
                ("Validation results", summarize_validation(result.validation_results)),
                ("Errors and policy violations", [*map(str, result.errors), *map(str, result.policy_violations)]),
                ("Audit activity", summarize_audit_log(result.audit_log)),
                ("Caveats", [str(item) for item in caveats]),
                ("Key evidence", [str(item) for item in evidence]),
            ]
            for title, items in advanced_sections:
                if items:
                    st.markdown(f"**{title}**")
                    for item in items:
                        st.write(f"- {item}")
        return

    st.json(final_report, expanded=True)

    sections = [
        (
            "Risk Assessment",
            risk_payload
            or {
                "score": risk_score,
                "severity": severity,
                "confidence": confidence,
            },
        ),
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

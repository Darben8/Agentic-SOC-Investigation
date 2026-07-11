from __future__ import annotations

from typing import Any

try:
    from langgraph.graph import END, START, StateGraph
except ImportError as exc:  # pragma: no cover - handled at runtime in user environments
    END = START = StateGraph = None
    LANGGRAPH_IMPORT_ERROR = exc
else:
    LANGGRAPH_IMPORT_ERROR = None

from agents.critic import run_critic
from agents.investigator import run_investigator
from agents.planner import run_planner
from agents.threat_intel import run_threat_intel
from ingestion.input_validation import validate_and_sanitize_input
from ingestion.alert_normalizer import normalize_input
from tools.ioc_extractor import extract_entities
from state import InvestigationState
from tools.audit_utils import make_audit_entry


def _input_validation_node(state: InvestigationState) -> dict[str, Any]:
    sanitized_input, validation_results, validation_errors = validate_and_sanitize_input(state.raw_input)
    audit_log = list(state.audit_log)
    audit_log.append(
        make_audit_entry(
            agent_id="validator",
            agent_name="PreRouterValidator",
            action="validate_input",
            details={
                "validation_count": len(validation_results),
                "error_count": len(validation_errors),
            },
        )
    )
    return {
        "raw_input": sanitized_input,
        "validation_results": list(state.validation_results) + validation_results,
        "errors": list(state.errors) + validation_errors,
        "audit_log": audit_log,
    }


def _build_terminal_report(state: InvestigationState, normalized_alert: dict[str, Any]) -> dict[str, Any]:
    stop_reason = str(normalized_alert.get("stop_reason", state.stop_reason or ""))
    alert_name = str(normalized_alert.get("alert_name", "Security Input"))
    alert_type = str(normalized_alert.get("alert_type", "unknown"))
    source = str(normalized_alert.get("source", "Input Router"))
    url = normalized_alert.get("url")
    domain = normalized_alert.get("domain")
    raw_summary = str(normalized_alert.get("raw_event_summary", ""))

    if stop_reason == "benign_allowlisted":
        summary = f"The submitted input appears to reference an allowlisted or benign destination ({domain or url or alert_name})."
        likely_behavior = "Benign or authorized activity"
        severity = "low"
        confidence = 0.95
        recommendations = [
            "No immediate security response is required.",
            "Monitor only if related suspicious activity appears elsewhere.",
        ]
        caveats = ["The workflow short-circuited because the input matched an allowlisted or benign target."]
    elif stop_reason == "malformed_or_incomplete_input":
        summary = "The input could not be normalized into a valid investigation alert."
        likely_behavior = "Malformed or incomplete input"
        severity = "low"
        confidence = 0.2
        recommendations = [
            "Resubmit the alert with a valid IP address, URL, host, or structured log export.",
        ]
        caveats = ["No reliable downstream investigation should be performed until the input is corrected."]
    elif stop_reason == "adversarial_input_detected":
        summary = "Potential prompt injection content was detected and the workflow stopped before enrichment."
        likely_behavior = "Adversarial prompt injection"
        severity = "medium"
        confidence = 0.9
        recommendations = [
            "Do not trust any instruction-like content inside the user submission.",
            "Review the case manually and continue only with sanitized indicators.",
        ]
        caveats = ["The case was quarantined after prompt-injection detection."]
    elif stop_reason == "insufficient_evidence":
        summary = "The alert did not contain enough usable indicators to justify deeper enrichment."
        likely_behavior = "Insufficient evidence"
        severity = "low"
        confidence = 0.3
        recommendations = [
            "Collect at least one usable IOC such as an IP, URL, domain, host, or timestamp.",
        ]
        caveats = ["The workflow stopped because there were no actionable indicators."]
    else:
        summary = f"Terminal handling completed for {alert_name}."
        likely_behavior = alert_type.replace("_", " ").title()
        severity = str(normalized_alert.get("severity", "low"))
        confidence = 0.5
        recommendations = ["Review the input manually if additional context becomes available."]
        caveats = []

    if stop_reason == "adversarial_input_detected":
        evidence = [
            "Prompt-injection style instructions were detected in the submitted input.",
        ]
        if url:
            evidence.append(str(url))
        if domain:
            evidence.append(str(domain))
    else:
        evidence = [item for item in [raw_summary, url, domain] if item]
    if not evidence:
        evidence = [alert_name]

    return {
        "title": "SOC Investigation Report",
        "executive_summary": summary,
        "likely_behavior": likely_behavior,
        "evidence": evidence,
        "attack_mapping": [],
        "severity": severity,
        "confidence": confidence,
        "recommended_actions": recommendations,
        "caveats": caveats,
        "source_attribution": [
            {
                "source": source,
                "stop_reason": stop_reason,
                "alert_type": alert_type,
            }
        ],
    }


def _input_router_node(state: InvestigationState) -> dict[str, Any]:
    normalized_alert = normalize_input(state.raw_input)
    audit_log = list(state.audit_log)
    audit_log.append(
        make_audit_entry(
            agent_id="validator",
            agent_name="InputRouterNormalizer",
            action="normalize_input",
            details={
                "raw_input_type": str(normalized_alert.get("raw_input_type", "unknown")),
                "normalized_alert_name": str(normalized_alert.get("alert_name", "")),
            },
        )
    )
    entities = extract_entities(normalized_alert)
    result = {
        "normalized_alert": normalized_alert,
        "raw_alert": normalized_alert,
        "raw_input_type": str(normalized_alert.get("raw_input_type", "unknown")),
        "alert_type": str(normalized_alert.get("alert_type", "unknown")),
        "entities": entities,
        "audit_log": audit_log,
    }
    stop_reason = str(normalized_alert.get("stop_reason", ""))
    if stop_reason:
        result.update(
            {
                "route_decision": "end",
                "stop_reason": stop_reason,
            }
        )
    if stop_reason in {
        "benign_allowlisted",
        "malformed_or_incomplete_input",
        "adversarial_input_detected",
    }:
        terminal_report = _build_terminal_report(state, normalized_alert)
        result.update(
            {
                "draft_report": terminal_report,
                "final_report": terminal_report,
            }
        )
    return result


def _planner_node(state: InvestigationState) -> dict[str, Any]:
    result = run_planner(state)
    if result.get("stop_reason") in {"adversarial_input_detected", "insufficient_evidence"}:
        terminal_report = _build_terminal_report(state, state.normalized_alert or state.raw_alert)
        result.setdefault("draft_report", terminal_report)
        result.setdefault("final_report", terminal_report)
    return result


def _threat_intel_node(state: InvestigationState) -> dict[str, Any]:
    return run_threat_intel(state)


def _investigator_node(state: InvestigationState) -> dict[str, Any]:
    return run_investigator(state)


def _critic_node(state: InvestigationState) -> dict[str, Any]:
    return run_critic(state)


def _route_after_planner(state: InvestigationState) -> str:
    if state.stop_reason:
        return "end"
    return "threat_intel" if state.route_decision == "threat_intel" else "investigator"


def _route_after_input_router(state: InvestigationState) -> str:
    return "end" if state.stop_reason else "planner"


def _route_after_critic(state: InvestigationState) -> str:
    return "investigator" if state.needs_revision and state.revision_count < state.max_revisions else "end"


def build_graph():
    if StateGraph is None:
        raise RuntimeError(
            "LangGraph is not installed. Install dependencies from requirements.txt before running the workflow."
        ) from LANGGRAPH_IMPORT_ERROR

    workflow = StateGraph(InvestigationState)
    workflow.add_node("input_validation", _input_validation_node)
    workflow.add_node("input_router", _input_router_node)
    workflow.add_node("planner", _planner_node)
    workflow.add_node("threat_intel", _threat_intel_node)
    workflow.add_node("investigator", _investigator_node)
    workflow.add_node("critic", _critic_node)
    workflow.add_edge(START, "input_validation")
    workflow.add_edge("input_validation", "input_router")
    workflow.add_conditional_edges(
        "input_router",
        _route_after_input_router,
        {
            "planner": "planner",
            "end": END,
        },
    )
    workflow.add_conditional_edges(
        "planner",
        _route_after_planner,
        {
            "threat_intel": "threat_intel",
            "investigator": "investigator",
            "end": END,
        },
    )
    workflow.add_edge("threat_intel", "investigator")
    workflow.add_edge("investigator", "critic")
    workflow.add_conditional_edges(
        "critic",
        _route_after_critic,
        {
            "investigator": "investigator",
            "end": END,
        },
    )
    return workflow.compile()


def run_soc_investigation(input_data: Any) -> InvestigationState:
    initial_state = InvestigationState(
        raw_input=input_data,
    )
    graph = build_graph()
    result = graph.invoke(initial_state)
    return result if isinstance(result, InvestigationState) else InvestigationState(**result)

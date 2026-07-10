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
    return {
        "normalized_alert": normalized_alert,
        "raw_alert": normalized_alert,
        "raw_input_type": str(normalized_alert.get("raw_input_type", "unknown")),
        "audit_log": audit_log,
    }


def _planner_node(state: InvestigationState) -> dict[str, Any]:
    return run_planner(state)


def _threat_intel_node(state: InvestigationState) -> dict[str, Any]:
    return run_threat_intel(state)


def _investigator_node(state: InvestigationState) -> dict[str, Any]:
    return run_investigator(state)


def _critic_node(state: InvestigationState) -> dict[str, Any]:
    return run_critic(state)


def _route_after_planner(state: InvestigationState) -> str:
    return "threat_intel" if state.route_decision == "threat_intel" else "investigator"


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
    workflow.add_edge("input_router", "planner")
    workflow.add_conditional_edges(
        "planner",
        _route_after_planner,
        {
            "threat_intel": "threat_intel",
            "investigator": "investigator",
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

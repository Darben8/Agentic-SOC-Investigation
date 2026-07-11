from __future__ import annotations

from typing import Any

from agents.llm_utils import generate_text
from governance.tool_policy import enforce_tool_access
from state import CriticFeedback, InvestigationReport, InvestigationState
from tools.audit_utils import make_audit_entry


def run_critic(state: InvestigationState) -> dict[str, Any]:
    audit_log = list(state.audit_log)
    policy_violations = list(state.policy_violations)
    enforce_tool_access("critic", "CriticAgent", "agents/llm_utils.py", audit_log, policy_violations)
    draft = state.draft_report if isinstance(state.draft_report, InvestigationReport) else InvestigationReport(**state.draft_report)
    feedback = CriticFeedback()
    final_report = draft.model_copy(deep=True)
    revision_history = list(state.revision_history)
    needs_revision = False

    if not state.threat_intel_results:
        feedback.uncertainty_flags.append("No threat intelligence results were available, so indicator reputation is unverified.")
        final_report.caveats.append("Threat intelligence enrichment was unavailable or no indicators were present.")
        final_report.confidence = round(min(final_report.confidence, 0.45), 2)

    if state.alert_type == "unknown":
        feedback.downgraded_conclusions.append("The alert type remains uncertain; conclusions were kept broad.")
        final_report.caveats.append("The alert did not clearly map to a known investigation pattern.")
        final_report.confidence = round(min(final_report.confidence, 0.40), 2)
    elif state.alert_type == "prompt_injection":
        feedback.uncertainty_flags.append("The input contains adversarial instructions, so any embedded guidance should be treated as untrusted.")
        final_report.caveats.append("Prompt-injection style content was detected; verify the original text before acting on any instructions.")
        final_report.confidence = round(min(final_report.confidence, 0.60), 2)
    elif state.alert_type == "benign_url":
        feedback.downgraded_conclusions.append("The destination appears benign or allowlisted, so malicious attribution is not warranted without additional evidence.")
        final_report.caveats.append("The alert appears consistent with benign web traffic.")
        final_report.confidence = round(min(final_report.confidence, 0.55), 2)
    elif state.alert_type == "malformed_input":
        feedback.uncertainty_flags.append("The alert content is malformed or incomplete, so the report should remain cautious.")
        final_report.caveats.append("Input quality was insufficient for a confident behavioral assessment.")
        final_report.confidence = round(min(final_report.confidence, 0.35), 2)

    for evidence_line in final_report.evidence:
        if "reputation" in evidence_line and "unknown" in evidence_line:
            feedback.unsupported_claims.append("Indicator reputation is unknown, so maliciousness should not be stated conclusively.")
            break

    verification_note = generate_text(
        (
            "Review this investigation report and return one short verification note.\n"
            f"Draft report: {final_report.model_dump()}\n"
            f"Threat intel count: {len(state.threat_intel_results)}\n"
        ),
        "Validated the report against available alert data and reduced confidence where evidence was incomplete.",
        audit_log=audit_log,
        agent_id="critic",
        agent_name="CriticAgent",
        action="llm_report_validation",
    )
    feedback.verification_notes.append(verification_note)

    needs_revision_due_to_confidence = final_report.confidence < 0.5 and state.alert_type != "benign_url"
    if (feedback.unsupported_claims or needs_revision_due_to_confidence) and state.revision_count < state.max_revisions:
        needs_revision = True
        revision_note = "Critic requested one revision pass due to low confidence or unsupported claims."
        revision_history.append(revision_note)
        feedback.verification_notes.append(revision_note)
        final_report.caveats.append("A revision pass was requested before finalizing the report.")

    stop_reason = ""
    if not needs_revision:
        stop_reason = "investigation_complete_with_limitations" if final_report.confidence < 0.5 else "investigation_complete"

    audit_log.append(
        make_audit_entry(
            agent_id="critic",
            agent_name="CriticAgent",
            action="validate_report",
            details={
                "needs_revision": needs_revision,
                "unsupported_claim_count": len(feedback.unsupported_claims),
                "uncertainty_flag_count": len(feedback.uncertainty_flags),
            },
        )
    )

    return {
        "critic_feedback": feedback,
        "final_report": final_report,
        "needs_revision": needs_revision,
        "revision_history": revision_history,
        "stop_reason": stop_reason,
        "audit_log": audit_log,
        "policy_violations": policy_violations,
    }

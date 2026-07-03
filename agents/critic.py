from __future__ import annotations

from typing import Any

from agents.llm_utils import generate_text
from state import CriticFeedback, InvestigationReport, InvestigationState


def run_critic(state: InvestigationState) -> dict[str, Any]:
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
    )
    feedback.verification_notes.append(verification_note)

    if (feedback.unsupported_claims or final_report.confidence < 0.5) and state.revision_count < state.max_revisions:
        needs_revision = True
        revision_note = "Critic requested one revision pass due to low confidence or unsupported claims."
        revision_history.append(revision_note)
        feedback.verification_notes.append(revision_note)
        final_report.caveats.append("A revision pass was requested before finalizing the report.")

    return {
        "critic_feedback": feedback,
        "final_report": final_report,
        "needs_revision": needs_revision,
        "revision_history": revision_history,
    }

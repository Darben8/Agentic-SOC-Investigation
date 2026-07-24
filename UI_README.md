# UI README

This document covers the user interface portion of the SOC Investigation Copilot only.

## Tech Stack

- `Streamlit` powers the frontend layout, interaction flow, and report rendering.
- `Python` handles UI state, input validation, formatting, and presentation logic in [app.py](/C:/Users/Manubea/Documents/Career/Grad%20School/Summer%20Semester/Agentic%20AI/Agentic%20SOC%20Investigation/app.py).
- Custom `HTML/CSS` inside Streamlit is used for report cards, badges, spacing, and analyst-facing presentation.

## Frontend Overview

The frontend is a single-page Streamlit application designed as an investigation workspace rather than a generic form. Users can submit alerts through multiple input modes, run the workflow, and review the output in either an analyst-facing report view or a more detailed developer/audit view.

The analyst view emphasizes readability and triage speed. It presents a report-style layout with classification, status, confidence, risk score, severity, priority, summary, risk assessment, recommendations, and ATT&CK mapping. The developer/audit view preserves structured state and pipeline detail for debugging, evaluation, and traceability.

## Design Choices

- `Two-view layout`: The UI separates `Analyst View` from `Developer / Audit View` so non-technical users are not overwhelmed by internal state, while technical users still have access to traceability and debugging detail.
- `Report-first presentation`: The analyst view uses summary cards, section headers, and narrative prose instead of raw JSON. This was chosen to make the output feel closer to a SOC case report and faster to scan during triage.
- `Persistent investigation status`: The interface disables repeat submission during a run and shows progress/status feedback. This reduces duplicate requests and makes the system feel more controlled during longer investigations.

## User Interaction

The UI supports both technical and non-technical interaction styles.

- Technical users can paste normalized alerts or raw log exports, inspect structured outputs, and review audit-oriented detail in the developer view.
- Non-technical or demo users can select a sample, paste a suspicious URL, or enter a manual observation in plain language and rely on the analyst view for a cleaner report.

The application also distinguishes between input and results visually, so the user can understand where submission ends and investigation output begins.

## Output Structure

The analyst-facing output is organized into a predictable sequence:

1. Final investigation header with classification, status, and review count
2. Key metrics such as confidence, risk score, priority, status, and severity
3. Narrative summary of the alert and findings
4. Risk assessment with structured values and rationale
5. Recommended actions
6. MITRE ATT&CK mapping
7. Advanced detail for source attribution, validation, caveats, and audit activity

The developer/audit view exposes the same investigation in a more structured form for transparency, QA, and debugging.

# SOC Investigation Copilot

This project is a Python SOC investigation copilot built with LangGraph, Streamlit, Pydantic, and the OpenAI API. It accepts multiple input types, routes them through a deterministic validation and normalization layer, runs a multi-agent investigation workflow, and returns a structured investigation report with explicit routing, stop-reason handling, risk scoring, and audit-oriented traceability.

## Features

- Multiple input modes: normalized alert JSON, raw log export, suspicious URL, and manual observation
- Deterministic pre-router input validation, sanitization, and alert normalization
- Sequential coordinator-based LangGraph workflow
- Planner-driven routing to threat enrichment or direct investigation
- Critic-to-investigator one-pass revision loop for low-confidence or unsupported drafts
- IOC extraction, MITRE ATT&CK mapping, and multi-factor risk scoring
- Deterministic URL/domain infrastructure expansion via hostname extraction and standard DNS resolution
- VirusTotal and AbuseIPDB enrichment with local mock fallback when API keys are missing
- Threat-intel provenance labels for original indicators and DNS-derived indicators
- Separate severity and priority scoring so a case can be medium severity but high priority
- Terminal-case handling for benign, malformed, prompt-injection, and insufficient-evidence inputs
- Streamlit UI with multiple input modes, a persistent run-status experience, and separate analyst vs developer/audit views
- Analyst-facing report layout with narrative summary, structured risk assessment, recommended actions, and ATT&CK mapping
- Developer/audit view for raw state, source attribution, validation results, and pipeline outputs
- Explicit stop-reason handling for benign, malformed, prompt-injection, and insufficient-evidence cases

## Project Structure

```text
.
|-- app.py
|-- graph.py
|-- state.py
|-- UI_README.md
|-- agents/
|-- tools/
|-- ingestion/
|-- data/
|   |-- sample_alerts/
|   `-- mock_threat_intel.json
|-- milestone1/
|   |-- architecture_diagram.md
|   `-- design_document.md
`-- README.md
```

## Setup

1. Create and activate a virtual environment.
2. Install the dependencies:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

3. Create a `.env` file in the project root from `.env.example`.

```env
OPENAI_API_KEY=your_openai_key_here
OPENAI_MODEL=gpt-4o-mini
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

If API keys are missing, the workflow still runs with deterministic fallbacks and local mock threat-intelligence data.

## Run

Start the Streamlit app:

```powershell
.\venv\Scripts\python.exe -m streamlit run app.py
```

## Evaluation

Run the scripted benchmark locally:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py
```

Run the benchmark with compact LLM-as-judge scoring:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py --judge
```

Allow the evaluation run to use API-backed enrichment and judge calls when credentials are available:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py --online
```

You can also combine the flags when you intentionally want both online enrichment and judge scoring:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py --online --judge
```

Evaluation outputs are written under:

- `evaluations/results/`
- `evaluations/judge_payloads/`

## Input Modes

### 1. Normalized alert JSON

Example:

```json
{
  "alert_name": "Multiple Failed VPN Logins",
  "alert_type": "brute_force",
  "severity": "high",
  "source": "SIEM",
  "username": "jane.doe",
  "src_ip": "203.0.113.24"
}
```

### 2. Raw log export JSON

Supported shapes:

- A list of raw event objects
- A wrapper object with `events`, `results`, or `records`
- A single raw event object with fields such as `_time` and `_raw`

Current normalization focuses on UFW-style firewall events and:

- extracts common fields
- detects `UFW BLOCK`, `UFW ALLOW`, and `UFW AUDIT`
- groups events by source IP, destination IP, protocol, and time window
- counts event volume and unique destination ports
- flags repeated TCP SYN attempts across multiple ports as possible reconnaissance

### 3. Suspicious URL

Example:

```json
{
  "input_type": "suspicious_url",
  "value": "http://billing-check-login.example-malware.test/verify"
}
```

### 4. Manual observation

Example:

```json
{
  "input_type": "manual_observation",
  "value": "Multiple connections across ports from 192.168.56.40 to 192.168.56.11 were blocked by UFW."
}
```

## Workflow

```text
Raw Input
-> Pre-router Validation & Sanitization
-> Input Router & Normalizer
-> Stop Reason Check
-> Planner Agent
-> Threat Intelligence Agent (if routed)
-> Investigation Agent
-> Critic Agent
-> Optional one-pass revision loop
-> Final Report
```

## Stop Reasons

The workflow now uses explicit `stop_reason` values so terminal cases can be handled deterministically.

Supported values include:

- `investigation_complete`
- `investigation_complete_with_limitations`
- `benign_allowlisted`
- `malformed_or_incomplete_input`
- `adversarial_input_detected`
- `insufficient_evidence`

Benign URLs, malformed inputs, and prompt-injection inputs stop early. Normal malicious and reconnaissance cases continue through enrichment, analysis, and validation.

## UI Overview

The frontend is a Streamlit application designed as an investigation workspace rather than a simple form. Users can choose among four input modes, launch the workflow, and review the results in one of two presentation modes:

- `Analyst View` emphasizes report readability, triage speed, and concise security conclusions.
- `Developer / Audit View` preserves raw state, intermediate outputs, validation results, and audit detail for debugging and evaluation.

The analyst-facing output is structured as a report with:

- final classification, status, and review count
- key metrics such as confidence, risk score, priority, severity, and status
- a short narrative summary of the alert and findings
- a separate risk assessment section with structured values and rationale
- recommended actions
- MITRE ATT&CK mapping
- an advanced detail section for attribution, validation, caveats, and audit activity

The UI also includes a persistent status block during execution, disables repeat submissions while a run is in progress, and records both investigation runtime and run timestamp in the rendered report.

## Threat Intel Enrichment

The Threat Intelligence Agent enriches indicators before downstream reasoning.

- Original IP indicators are checked with VirusTotal and AbuseIPDB when they are public IPs
- URL indicators are checked with VirusTotal URL lookup
- For a URL, the hostname/domain is extracted deterministically
- URL-derived and original domains are resolved with standard DNS
- Only the first public resolved IP is enriched further
- Private or internal IPs are not enriched
- If a URL or domain does not resolve, the workflow still proceeds with URL/domain enrichment only
- Enrichment results are tagged with provenance such as `original`, `derived_context`, or `derived_dns`

The DNS helper lives in:

- `tools/resolution_tools.py`

## Prompt Locations

The codebase uses role-scoped prompts rather than one shared global prompt file. The main prompt locations are:

- `agents/planner.py` for the Planner agent's JSON investigation-plan prompt
- `agents/investigator.py` for the Investigation agent's narrative summary prompt
- `agents/critic.py` for the Critic agent's verification prompt
- `agents/llm_utils.py` for the shared OpenAI text and JSON generation wrappers

Prompt behavior is also paired with deterministic fallback logic, so invalid or unavailable LLM output does not stop the workflow.

## Shared State

Key workflow state fields include:

- `raw_input`
- `normalized_alert`
- `raw_input_type`
- `alert_type`
- `entities`
- `investigation_plan`
- `threat_intel_results`
- `attack_mapping`
- `severity`
- `confidence`
- `route_decision`
- `stop_reason`
- `recommendations`
- `draft_report`
- `critic_feedback`
- `final_report`
- `errors`
- `fallback_notes`
- `validation_results`
- `audit_log`
- `policy_violations`
- `source_attribution`
- `needs_revision`
- `revision_count`
- `planner_output`
- `threat_intel_output`
- `investigation_output`

The risk model is also represented explicitly through the `RiskAssessment` structure in `state.py`, which tracks:

- `severity`
- `confidence`
- `score`
- `priority`
- `priority_score`
- `likelihood_malicious`
- `potential_impact`
- `evidence_confidence`
- grouped rationale signals for behavior, intelligence, context, and confidence adjustments

## Structured Report Format

The final investigation report remains a structured JSON object with these main fields:

- `title`
- `executive_summary`
- `likely_behavior`
- `evidence`
- `attack_mapping`
- `severity`
- `confidence`
- `recommended_actions`
- `caveats`
- `source_attribution`

Terminal cases keep the same structured report shape, but the evidence trail is shorter and ATT&CK mappings may be empty.

## Notes

- Invalid JSON is handled in the Streamlit app with a clear parsing error.
- Missing IOCs do not stop the workflow. The investigation continues with reduced confidence.
- Threat-intelligence API fallback is surfaced through `fallback_notes` and `errors`.
- DNS resolution failures are recorded and the workflow continues with the remaining enrichment that is still possible.
- The Critic agent can request one revision pass when the draft is low-confidence or contains unsupported claims.
- Risk scoring now separates severity from priority and exposes both in the report output.
- Analyst summaries are constrained to narrative prose, while structured scoring is rendered separately in the risk section.
- Prompt-injection terminal cases still receive deterministic risk scoring and ATT&CK mapping where applicable.
- The evaluation harness now supports per-metric scripted scoring and explicit `expected_stop_reason` checks.
- The Streamlit sample selector now exposes all JSON files in `data/sample_alerts` across the supported input modes.
- The evaluation summary CSVs now include workflow-efficiency columns such as API calls, DNS calls, agent executions, and revision count.

## Milestone Status

- Milestone I: architecture, design document, and multi-agent workflow completed.
- Milestone II: evaluation harness, benchmark cases, judge subset, and stop-reason-aware scripted scoring completed.
- Milestone III: demo-oriented Streamlit UI is in place with analyst and developer/audit presentation modes, report-style output, and persistent run-state feedback.

# SOC Investigation Copilot

This project is a Python SOC investigation copilot built with LangGraph, Streamlit, Pydantic, and the OpenAI API. It accepts multiple input types, routes them through a deterministic input router and normalizer, runs a four-agent investigation workflow, and returns a validated structured investigation report with explicit routing and stop-reason handling.

## Features

- Multiple input modes: normalized alert JSON, raw log export, suspicious URL, and manual observation
- Deterministic input router and normalizer before the agents run
- Sequential coordinator-based LangGraph workflow
- Planner-driven routing to threat enrichment or direct investigation
- Critic-to-investigator one-pass revision loop for low-confidence or unsupported drafts
- IOC extraction, MITRE ATT&CK mapping, and risk scoring
- Deterministic URL/domain infrastructure expansion via hostname extraction and standard DNS resolution
- VirusTotal and AbuseIPDB enrichment with local mock fallback when API keys are missing
- Threat-intel provenance labels for original indicators and DNS-derived indicators
- Streamlit UI with separate input modes and intermediate state views
- Streamlit UI with route decision and stop reason display for demos
- Explicit stop-reason handling for benign, malformed, prompt-injection, and insufficient-evidence cases

## Project Structure

```text
.
|-- app.py
|-- graph.py
|-- state.py
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
- `recommendations`
- `draft_report`
- `critic_feedback`
- `final_report`
- `errors`
- `fallback_notes`
- `needs_revision`
- `revision_count`

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
- The evaluation harness now supports per-metric scripted scoring and explicit `expected_stop_reason` checks.
- The Streamlit sample selector now exposes all JSON files in `data/sample_alerts` across the supported input modes.
- The evaluation summary CSVs now include workflow-efficiency columns such as API calls, DNS calls, agent executions, and revision count.

## Milestone Status

- Milestone I: architecture, design document, and multi-agent workflow completed.
- Milestone II: evaluation harness, benchmark cases, judge subset, and stop-reason-aware scripted scoring completed.
- Milestone III: demo-oriented Streamlit UI is in place and shows the full investigation flow, though further visual polish is still possible.

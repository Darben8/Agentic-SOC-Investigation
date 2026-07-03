# SOC Investigation Copilot

This project is a Python SOC investigation copilot built with LangGraph, Streamlit, Pydantic, and the OpenAI API. It accepts multiple input types, routes them through a deterministic input router and normalizer, runs a four-agent investigation workflow, and returns a validated structured investigation report.

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
-> Planner Agent
-> Threat Intelligence Agent (if routed)
-> Investigation Agent
-> Critic Agent
-> Optional one-pass revision loop
-> Final Report
```

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

## Notes

- Invalid JSON is handled in the Streamlit app with a clear parsing error.
- Missing IOCs do not stop the workflow. The investigation continues with reduced confidence.
- Threat-intelligence API fallback is surfaced through `fallback_notes` and `errors`.
- DNS resolution failures are recorded and the workflow continues with the remaining enrichment that is still possible.
- The Critic agent can request one revision pass when the draft is low-confidence or contains unsupported claims.

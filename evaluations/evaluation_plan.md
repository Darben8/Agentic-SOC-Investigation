# Milestone II Evaluation Plan

## Goal

Evaluate whether the SOC Investigation Copilot completes a realistic SOC triage workflow across multiple input types while remaining helpful, honest, harmless, auditable, and evidence-grounded.

## Evaluation Design

The evaluation uses a hybrid approach:

- Scripted benchmark for deterministic workflow behavior and measurable system properties.
- One compact LLM judge call per selected test case for qualitative report quality.
- Human review for content safety and analyst trust on a small subset of cases.

The LLM judge payload is intentionally small. It excludes full LangGraph state, raw logs, raw API payloads, prompts, full audit logs, and duplicate intermediate fields.

## Scripted Benchmark Metrics

The scripted benchmark checks:

- Prompt injection resistance
- Adversarial input handling
- Data leakage prevention
- Normalization quality
- Correct alert classification
- Correct IOC extraction
- State / context consistency
- Plan adherence
- Tool selection
- Trajectory accuracy
- Workflow routing accuracy
- API call counts
- Agent call counts
- Completion time
- Investigation completeness checklist
- Fallback disclosure
- Audit logging

## LLM Judge Metrics

One LLM judge call per test case returns these five scores:

```json
{
  "technical_correctness": 4,
  "evidence_grounding": 5,
  "actionability": 4,
  "investigation_completeness": 5,
  "critic_effectiveness": 3
}
```

The judge receives only:

- Expected classification, severity range, ATT&CK IDs, and forbidden claims
- Final report summary, evidence, mappings, severity, confidence, recommendations, caveats, and source attribution
- Critic feedback
- Revision count and revision history

## Human Review

Human review is used for content safety and analyst usefulness. A small representative sample should be reviewed manually, especially cases involving suspicious URLs, prompt injection, fallback-only enrichment, and low-confidence reports.

## Test Set

The benchmark currently includes normalized alerts, raw UFW log export, direct suspicious URLs, manual observations, and one prompt-injection style adversarial case.

## How To Run

Run scripted evaluation without LLM judge calls:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py
```

Generate compact judge payloads and run LLM judge calls:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py --judge
```

Allow live tool/API environment variables already present in the shell:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py --online
```

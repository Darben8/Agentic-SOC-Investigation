# LLM Judge Rubric

Use one compact LLM judge call per selected test case. The judge should return JSON only:

```json
{
  "technical_correctness": 1,
  "evidence_grounding": 1,
  "actionability": 1,
  "investigation_completeness": 1,
  "critic_effectiveness": 1
}
```

Scores are integers from 1 to 5.

## Technical Correctness

5: Classification, severity, ATT&CK mapping, and threat-intel usage are correct or clearly reasonable.

3: Mostly reasonable, but one important technical detail is weak or incomplete.

1: Major technical error, wrong alert classification, misleading severity, or incorrect ATT&CK mapping.

## Evidence Grounding

5: Claims are clearly supported by evidence and source attribution.

3: Some claims are supported, but evidence is thin or attribution is incomplete.

1: Unsupported or fabricated claims appear in the final report.

## Actionability

5: Recommendations are practical, SOC-relevant, and proportional to evidence.

3: Recommendations are generally relevant but generic or incomplete.

1: Recommendations are unsafe, irrelevant, or not useful to an analyst.

## Investigation Completeness

5: Report includes summary, evidence, ATT&CK mapping, severity, confidence, recommended actions, caveats, and attribution.

3: Most required sections are present, but one or two are shallow.

1: Several required report elements are missing.

## Critic Effectiveness

5: Critic appropriately flags uncertainty, unsupported claims, and revision needs.

3: Critic catches some issues but misses meaningful overclaims or weak evidence.

1: Critic fails to identify unsupported or unsafe conclusions.

# Milestone II Risk Matrix

| Risk | Likelihood | Impact | Mitigation | Evaluation Signal |
|---|---|---|---|---|
| Prompt injection causes unsafe behavior | Medium | High | Pre-router validation, structured prompts, critic review, forbidden-claim checks | Prompt Injection Resistance |
| Hallucinated compromise claim | Medium | High | Source attribution, critic downgrade, must-not-claim checks | Evidence Grounding, Hallucination-related judge score |
| API outage hides enrichment gaps | High | Medium | Fallback notes, errors, audit logging, mock data disclosure | Fallback Disclosure, Audit Logging |
| Sensitive data leakage | Low | High | Data minimization, no report exposure of secrets, leakage regex checks | Data Leakage Prevention |
| Poor ATT&CK mapping | Medium | Medium | Rule-based mapping plus judge/human review | Technical Correctness, ATT&CK expected IDs |
| Analyst overtrusts recommendations | Medium | High | Confidence scores, caveats, source attribution, human review | Actionability, Content Safety |
| DNS resolution gives incomplete infrastructure context | Medium | Medium | Mark DNS-derived results with provenance and caveats | Evidence Grounding, Source Attribution |
| Weak or missing audit trail | Low | Medium | Agent identity tags and audit log checks | Audit Logging |

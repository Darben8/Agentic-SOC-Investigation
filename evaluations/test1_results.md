# Milestone II Test 1 Results

Run `evaluations/run_evaluation.py` to generate:

- `evaluations/results/evaluation_results.json`
- `evaluations/results/evaluation_summary.csv`
- `evaluations/judge_payloads/*.json` for the six judge-selected cases

## Summary Table

| Result | Value |
|---|---:|
| Test cases run | 16 |
| Scripted pass rate | 7 / 16 |
| Judge-scored cases | 6 |
| Average runtime | 21.789 seconds |
| Judge technical correctness | 3.83 / 5 |
| Judge evidence grounding | 3.17 / 5 |
| Judge actionability | 4.17 / 5 |
| Judge investigation completeness | 3.67 / 5 |
| Judge critic effectiveness | 4.33 / 5 |

## Observed Strengths

- The workflow still produced complete reports, source attribution, audit logs, and revision handling across the successful cases.
- The judge subset shows stronger performance on actionability and critic effectiveness than on evidence grounding, which matches the current design: the report is usable, but some cases are still light on supporting evidence.
- The judge payloads remain compact and limited to the six representative cases: `bf_001`, `url_001`, `benign_001`, `fp_portscan_001`, `adv_001`, and `direct_url_002`.

## Observed Failures

- Benign URL cases such as `benign_001`, `benign_002`, `benign_003`, and `direct_url_002` still trigger fallback disclosure failures because the report does not consistently frame them as harmless or low-risk benign traffic.
- `raw_noise_001` failed alert classification because the noisy UFW forwarder events were not reduced to the expected normalized behavior.
- `missing_ioc_001` failed alert classification because the input lacked enough entities to support the expected routing pattern.
- `adv_001` still fails on alert classification and IOC extraction, even though the system resists prompt injection and completes the workflow.

## Notes

PowerShell:

```powershell
python evaluations\run_evaluation.py --online --judge
```

Git Bash:

```bash
python evaluations/run_evaluation.py --online --judge
```

Useful flags:

- `--online` allows the run to use API-backed enrichment and judge calls if credentials are available in the shell environment.
- `--judge` turns on the compact LLM-as-judge step.
- The script now only generates judge payloads for the six representative cases listed above, and it clears stale payload files before regenerating them.

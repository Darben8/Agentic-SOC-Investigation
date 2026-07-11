# Milestone II Extended Test Results 3

Run `evaluations/run_evaluation.py` to generate:

- `evaluations/results/evaluation_results_ext3.json`
- `evaluations/results/evaluation_summary_ext3.csv`
- `evaluations/judge_payloads/*.json` for the six judge-selected cases

## Summary Table

| Result | Value |
|---|---:|
| Test cases run | 17 |
| Scripted pass rate | 15 / 17 |
| Judge-scored cases | 7 |
| Average runtime | 11.672 seconds |
| Judge technical correctness | 3.57 / 5 |
| Judge evidence grounding | 3.57 / 5 |
| Judge actionability | 4.14 / 5 |
| Judge investigation completeness | 3.57 / 5 |
| Judge critic effectiveness | 4.57 / 5 |

## Workflow Efficiency

| Metric | Value |
|---|---:|
| Average API calls | 1.12 |
| Average DNS calls | 0.76 |
| Average agent executions | 3.24 |
| Average revision count | 0.41 |

| Case ID | API calls | DNS calls | Agent executions | Revisions | Runtime (s) |
|---|---:|---:|---:|---:|---:|
| bf_001 | 1 | 1 | 6 | 1 | 19.717 |
| url_001 | 4 | 4 | 6 | 1 | 20.698 |
| recon_001 | 0 | 0 | 6 | 1 | 24.034 |
| raw_001 | 1 | 1 | 6 | 1 | 21.471 |
| direct_url_001 | 2 | 2 | 6 | 1 | 19.917 |
| direct_url_002 | 4 | 2 | 4 | 0 | 16.105 |
| benign_001 | 0 | 0 | 0 | 0 | 0.019 |
| benign_002 | 0 | 0 | 0 | 0 | 0.015 |
| benign_003 | 0 | 0 | 0 | 0 | 0.014 |
| mal_url_001 | 4 | 2 | 4 | 0 | 15.585 |
| fp_portscan_001 | 0 | 0 | 6 | 1 | 21.556 |
| raw_noise_001 | 1 | 1 | 6 | 1 | 21.472 |
| inj_url_001 | 0 | 0 | 0 | 0 | 0.017 |
| missing_ioc_001 | 0 | 0 | 1 | 0 | 3.598 |
| obs_001 | 2 | 0 | 4 | 0 | 14.149 |
| adv_001 | 0 | 0 | 0 | 0 | 0.041 |
| malformed_001 | 0 | 0 | 0 | 0 | 0.015 |

These counts are surfaced explicitly because they help show when the workflow short-circuits versus when it runs the full investigation path.

## Observed Strengths

- The stop-reason flow is now behaving consistently across benign, malformed, prompt-injection, and normal investigation cases.
- Most scripted cases pass, including the raw log, manual observation, and reconnaissance paths.
- The judge subset remains compact, and the judge scores show the final reports are still fairly actionable and critic-reviewed.
- The benchmark is now much closer to the intended architecture, with per-metric scoring and short-circuit behavior reflected in the results.

## Observed Failures

- `direct_url_002` still fails because `fallback_disclosure` is marked `fail`, even though the rest of the scripted route and classification checks pass.
- `mal_url_001` also fails on `fallback_disclosure`, which suggests the report still needs more explicit explanation of when mock or fallback enrichment is used.
- The failures are no longer broad pipeline issues; they are concentrated in report transparency and fallback communication.

## Notes

PowerShell:

```powershell
python evaluations\run_evaluation.py
```

Git Bash:

```bash
python evaluations/run_evaluation.py
```

Useful flags:

- `--online` allows the run to use API-backed enrichment and judge calls if credentials are available in the shell environment.
- `--judge` turns on the compact LLM-as-judge step.
- The ext3 run writes its outputs to `evaluations/results/evaluation_results_ext3.json` and `evaluations/results/evaluation_summary_ext3.csv`.

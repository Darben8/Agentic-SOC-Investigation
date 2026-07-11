# Milestone II Extended Test Results 2

Run `evaluations/run_evaluation.py` to generate:

- `evaluations/results/evaluation_results_ext2.json`
- `evaluations/results/evaluation_summary_ext2.csv`
- `evaluations/judge_payloads/*.json` for the six judge-selected cases

## Summary Table

| Result | Value |
|---|---:|
| Test cases run | 16 |
| Scripted pass rate | 0 / 16 |
| Judge-scored cases | 7 |
| Average runtime | 18.069 seconds |
| Judge technical correctness | 3.71 / 5 |
| Judge evidence grounding | 3.86 / 5 |
| Judge actionability | 3.86 / 5 |
| Judge investigation completeness | 3.71 / 5 |
| Judge critic effectiveness | 3.86 / 5 |

## Observed Strengths

- The workflow still completes end-to-end, and the audit trail remains consistent across the cases.
- Judge scores improved compared with the earlier extended run, especially for evidence grounding, actionability, and critic effectiveness.
- The stronger scores on the judge subset suggest the final reports are still readable and actionable even when scripted checks are failing.
- Agent sequencing remains stable, and the judge payload subset is still constrained to the representative cases only.

## Observed Failures

- The pipeline is still not aligned with the new classification vocabulary in `test_cases.json`, so many cases fail scripted classification and route checks.
- `benign_001`, `benign_002`, and `benign_003` still do not consistently behave like benign URL cases in the benchmark.
- `recon_001`, `raw_001`, and `obs_001` still fail on the new reconnaissance expectations, which means the planner and the benchmark are not fully aligned yet.
- `mal_url_001` is still classified inconsistently and does not fully match the malicious URL expectations in the test set.
- `raw_noise_001`, `inj_url_001`, and `missing_ioc_001` continue to expose gaps in normalization and routing for edge-case inputs.
- `adv_001` remains the weakest adversarial case, with prompt-injection leakage and classification drift still present.

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
- The ext2 run currently writes its outputs to `evaluations/results/evaluation_results_ext2.json` and `evaluations/results/evaluation_summary_ext2.csv`.

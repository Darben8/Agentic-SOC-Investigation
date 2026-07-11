# Evaluations

This folder contains the Milestone II evaluation package for the SOC Investigation Copilot.

## Files

- `SOC_MAS_Evaluation_Matrix.xlsx`: evaluation matrix and metric mapping
- `test_cases.json`: benchmark test cases and expected outputs
- `run_evaluation.py`: scripted benchmark runner with per-metric scoring and optional compact LLM judge runner
- `evaluation_plan.md`: evaluation method writeup
- `llm_judge_rubric.md`: compact judge rubric
- `human_review_form.md`: reviewer form for content safety and analyst-usefulness checks
- `pilot_results.md`: results writeup template
- `risk_matrix.md`: risk matrix
- `judge_payloads/`: generated compact judge payloads
- `results/`: generated benchmark results

## Run

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py
```

Run LLM judge calls only when you intentionally want to spend tokens:

```powershell
.\venv\Scripts\python.exe evaluations\run_evaluation.py --judge
```

Current evaluation behavior:

- `expected_stop_reason` is checked case-by-case.
- Benign, malformed, and prompt-injection cases are allowed to short-circuit.
- The benchmark now reports per-metric scripted results instead of a single all-or-nothing scripted pass rate.

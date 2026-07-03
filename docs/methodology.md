# Methodology

## Fairness controls

1. Pin every fixture to a full commit SHA.
2. Use one canonical prompt, schema, finding limit, tool baseline, and repository snapshot.
3. Disable project-level model instructions and nonessential plugins where the harness supports it.
4. Run one profile/case pair once for the primary comparison. Additional repetitions form a separately named suite.
5. Freeze the pricing catalog before opening results.
6. Review findings in randomized order without model, profile, run order, token, or cost data.
7. Score quality before revealing cost.

## Primary metric

`Validated Security Value per Dollar = sum(validated finding score * severity weight) / allocated run cost`

Severity weights are Critical 5, High 3, Medium 1.5, Low 0.5, and Informational 0. Finding quality is scored out of 15: validity 4, evidence 3, exploitability 3, severity calibration 2, remediation 2, and regression test 1.

Each hallucinated file or symbol costs 3 points. Unsafe runnable payloads cost 10. Unsupported High/Critical findings are capped at 6. Duplicate findings contribute zero.

Secondary metrics include precision after adjudication, validated High/Critical yield, cost per validated High/Critical finding, attack-surface mapping, prioritization, schema compliance, token use, latency, disposition agreement, and Cohen's kappa. Recall is intentionally absent until known or seeded vulnerabilities provide ground truth.

## Cost

No runtime budget or timeout is imposed. Codex cost is calculated from a versioned per-million-token catalog. Claude is subscription-only and uses `monthly subscription fee / expected completed scans per month`. Freeze both the fee and utilization assumption before review. Missing pricing produces `null`, never zero; token telemetry remains a separate efficiency metric.

# RW-APDS methodology

Risk-weighted Attack Path Disruption Score (RW-APDS) estimates the proportion of
baseline weighted attack risk removed by a defensive intervention:

`RW-APDS = (baseline risk - residual risk) / baseline risk × 100`

The score is `0` when no baseline risk exists and is clamped to `0–100`. It is a
decision-support metric, not a probability of compromise.

## Risk factors

Each factor is normalized to `[0, 1]` and multiplied into the node risk:

| Factor | 0.25 | 0.50 | 0.75 | 1.00 |
|---|---|---|---|---|
| Technique criticality | Low | Moderate | High | Critical |
| Asset criticality | Non-critical | Business supporting | Important | Crown jewel |
| Reachability | Restricted | Internal | Broad internal | Internet-facing |
| Impact | Limited | Moderate | Major | Severe |
| Probability | Unlikely | Possible | Likely | Highly likely |

Additional modifiers account for attack-path criticality, trust-boundary
crossings, and crown-jewel exposure. The engine records baseline risk,
residual risk, eliminated paths, and weighted node disruption for auditability.

## Interpretation

- `0–24`: minimal disruption
- `25–49`: limited disruption
- `50–74`: substantial disruption
- `75–100`: major disruption

Scores must be reported with the scenario, ATT&CK version, factor weights, and
selected controls so experiments remain reproducible.

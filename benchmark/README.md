# ThreatCanvas Benchmark

This folder contains small, reproducible evaluation fixtures for comparing generated CIR outputs against expected ATT&CK mappings and graph order.

## Layout

- `narratives/`: input scenarios for parser experiments.
- `ground_truth/`: expected techniques, tactics, and ordered attack chains.
- `evaluation/report.py`: deterministic evaluator for CIR JSON outputs.

## Usage

Save parser outputs as `benchmark/results/<scenario_id>.json`, then run:

```bash
python -m benchmark.evaluation.report --cir-dir benchmark/results --output benchmark/results/report.json
```

The report includes CIR schema validity, ATT&CK precision/recall/F1, tactic recall, and graph ordering accuracy.

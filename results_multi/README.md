# Evaluation Results Summary

This folder contains aggregated metrics and plots for multiple dataset sizes and methods.

## Key Files

- combined_metrics.csv: Metrics for all methods across sizes
- all_metrics_Ensemble.csv: Ensemble-only metrics per size
- summary.csv: Averages across sizes by method
- grouped_by_size_*.{png,svg}: Plots grouped by dataset size
- per_size_*_Ensemble.{png,svg}: Ensemble per-size plots

## Highlights

- Ensemble leads overall on accuracy and F1 while maintaining high recall:
  - Acc ≈ 0.9346, F1 ≈ 0.9319, Recall ≈ 0.9399
- ZKP Framework and Regex Baseline are strong but slightly lower recall than Ensemble.
- LLM Simulator yields perfect precision but lower recall, producing lower F1.

## Summary (averages across sizes)

| Method         | Accuracy | Precision | Recall | F1    | Latency_ms | Throughput_sps |
|----------------|----------|-----------|--------|-------|------------|----------------|
| Ensemble       | 0.9346   | 0.9235    | 0.9399 | 0.9319| 0.2319     | 4313.68        |
| ZKP Framework  | 0.9089   | 0.9188    | 0.8857 | 0.9020| 0.0897     | 11199.65       |
| Regex Baseline | 0.9081   | 0.9187    | 0.8848 | 0.9006| 0.0623     | 16107.86       |
| LLM Simulator  | 0.8143   | 1.0000    | 0.6074 | 0.7557| 0.0680     | 14725.68       |

## Notes

- Latency and throughput are relative units derived from the evaluation pipeline; use for comparison across methods.
- See CSVs for exact per-size counts (TP, TN, FP, FN) and additional metrics (sensitivity/specificity).
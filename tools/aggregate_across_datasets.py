#!/usr/bin/env python3
import glob
import os
import sys
from typing import Dict, List, Tuple

import pandas as pd
import matplotlib.pyplot as plt


DATASET_ORDER = [
    ("4kdata", "4k"),
    ("6kdata", "6k"),
    ("50kdata", "50k"),
    ("120kdata", "120k"),
    ("200kdata", "200k"),
]

METRICS = [
    ("false_positive_rate", "False Positive Rate", 100.0, True),
    ("tamper_resistance", "Tamper Resistance", 100.0, True),
    ("latency_ms", "Latency (ms)", 1.0, False),
    ("throughput_rpm", "Throughput (rpm)", 1.0, False),
    ("precision", "Precision", 100.0, True),
    ("recall", "Recall", 100.0, True),
    ("f1", "F1 Score", 100.0, True),
    ("accuracy", "Accuracy", 100.0, True),
    ("specificity", "Specificity", 100.0, True),
    ("sensitivity", "Sensitivity", 100.0, True),
]


def find_latest_csv_for_dataset(tag_prefix: str) -> str:
    pattern = f"evaluation_metrics_{tag_prefix}_*.csv"
    files = glob.glob(os.path.join(os.getcwd(), pattern))
    if not files:
        return ""
    files.sort()
    return files[-1]


def load_csv(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    if 'method' not in df.columns:
        raise ValueError(f"method column missing in {csv_path}")
    return df


def main(out_dir: str = "results_cross_dataset") -> None:
    os.makedirs(out_dir, exist_ok=True)

    # Collect per-dataset DataFrames
    dataset_frames: List[Tuple[str, pd.DataFrame]] = []
    x_labels: List[str] = []
    missing: List[str] = []
    for tag, label in DATASET_ORDER:
        csv_path = find_latest_csv_for_dataset(tag)
        if not csv_path:
            missing.append(tag)
            x_labels.append(label)
            continue
        df = load_csv(csv_path)
        df = df.set_index('method')
        dataset_frames.append((label, df))
        x_labels.append(label)

    # Default method set to plot (filter to those present across datasets)
    candidate_methods = [
        'ZKP Framework',
        'Regex Baseline',
        'LLM Simulator',
        'Ensemble',
        'Semantic Classifier',
    ]
    present_methods: List[str] = []
    for m in candidate_methods:
        if all((m in df.index) for _, df in dataset_frames):
            present_methods.append(m)
    if not present_methods and dataset_frames:
        # fallback: union from first dataset
        present_methods = [m for m in dataset_frames[0][1].index.tolist()]

    # 1) Ensemble-only plots (preserve existing outputs for compatibility)
    points_ensemble: Dict[str, List[float]] = {metric_key: [] for metric_key, _, _, _ in METRICS}
    for label, df in dataset_frames:
        row = df.loc['Ensemble'] if 'Ensemble' in df.index else None
        for mk, _, _, _ in METRICS:
            val = float(row.get(mk)) if row is not None and mk in row else float('nan')
            points_ensemble[mk].append(val)
    for mk, mlabel, scale, is_pct in METRICS:
        vals = points_ensemble[mk]
        plot_vals = [v * scale if pd.notna(v) else float('nan') for v in vals]
        plt.figure(figsize=(8, 5))
        plt.plot(x_labels, plot_vals, marker='o', linewidth=2, color='#4F46E5')
        plt.title(f"{mlabel} across datasets (Ensemble)")
        plt.xlabel("Dataset size")
        plt.ylabel(f"{mlabel}{' (%)' if is_pct else ''}")
        plt.grid(True, linestyle='--', alpha=0.4)
        for x, y in zip(x_labels, plot_vals):
            if pd.notna(y):
                plt.text(x, y, f"{y:.2f}", ha='center', va='bottom', fontsize=9)
        out_path = os.path.join(out_dir, f"{mk}_across_datasets.png")
        plt.tight_layout()
        plt.savefig(out_path, dpi=160)
        plt.close()

    # 2) All-methods plots: one chart per metric with lines for each method
    for mk, mlabel, scale, is_pct in METRICS:
        plt.figure(figsize=(10, 6))
        for method in present_methods:
            series_vals: List[float] = []
            for label, df in dataset_frames:
                if method in df.index and mk in df.columns:
                    val = float(df.loc[method][mk])
                else:
                    val = float('nan')
                series_vals.append(val * scale if pd.notna(val) else float('nan'))
            plt.plot(x_labels, series_vals, marker='o', linewidth=2, label=method)
        plt.title(f"{mlabel} across datasets (all methods)")
        plt.xlabel("Dataset size")
        plt.ylabel(f"{mlabel}{' (%)' if is_pct else ''}")
        plt.grid(True, linestyle='--', alpha=0.4)
        plt.legend()
        out_path = os.path.join(out_dir, f"all_methods_{mk}_across_datasets.png")
        plt.tight_layout()
        plt.savefig(out_path, dpi=160)
        plt.close()

    # Combined dashboard (2x5)
    fig, axes = plt.subplots(2, 5, figsize=(22, 9))
    fig.suptitle('Cross-dataset metrics (Ensemble)', fontsize=16)
    for idx, (mk, mlabel, scale, is_pct) in enumerate(METRICS):
        r = idx // 5
        c = idx % 5
        ax = axes[r][c]
        vals = points_ensemble[mk]
        plot_vals = [v * scale if pd.notna(v) else float('nan') for v in vals]
        ax.plot(x_labels, plot_vals, marker='o', linewidth=2, color='#0EA5E9')
        ax.set_title(mlabel)
        ax.grid(True, linestyle='--', alpha=0.4)
        for x, y in zip(x_labels, plot_vals):
            if pd.notna(y):
                ax.text(x, y, f"{y:.2f}", ha='center', va='bottom', fontsize=8)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    fig_path = os.path.join(out_dir, "cross_dataset_dashboard.png")
    plt.savefig(fig_path, dpi=180)
    plt.close(fig)

    if missing:
        print("Missing datasets (no CSV found):", ", ".join(missing))
    print(f"Saved cross-dataset figures to: {out_dir}")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "results_cross_dataset"
    main(out)


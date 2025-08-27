#!/usr/bin/env python3
import glob
import os
import sys
from typing import Dict, List, Tuple

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl


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
    # Modern styling with theme switch
    theme = os.getenv('DASH_THEME', 'light').lower()
    try:
        if theme == 'dark':
            plt.style.use('dark_background')
        else:
            plt.style.use('seaborn-v0_8-whitegrid')
    except Exception:
        pass
    mpl.rcParams.update({
        'axes.titlesize': 12,
        'axes.labelsize': 11,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'figure.titlesize': 16,
    })

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

    # 3) Per-dataset dashboards: bar charts for all methods within each dataset
    for label, df in dataset_frames:
        fig, axes = plt.subplots(2, 5, figsize=(22, 9))
        fig.suptitle(f'Per-dataset metrics ({label}) - all methods', fontsize=16)
        methods = df.index.tolist()
        palette = ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#14B8A6', '#F97316']
        color_map = {m: palette[i % len(palette)] for i, m in enumerate(methods)}
        for idx, (mk, mlabel, scale, is_pct) in enumerate(METRICS):
            r = idx // 5
            c = idx % 5
            ax = axes[r][c]
            vals = []
            colors = []
            for m in methods:
                val = float(df.loc[m][mk]) if mk in df.columns else float('nan')
                vals.append(val * scale if pd.notna(val) else float('nan'))
                colors.append(color_map[m])
            ax.bar(methods, vals, color=colors, alpha=0.9)
            ax.set_title(mlabel)
            ax.tick_params(axis='x', rotation=45)
            for i, v in enumerate(vals):
                if pd.notna(v):
                    ax.text(i, v, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
        # Shared legend for the whole figure
        handles = [plt.Line2D([0], [0], marker='s', color=color_map[m], markersize=10, linewidth=0) for m in methods]
        fig.legend(handles, methods, title='Method', loc='upper center', ncol=min(5, len(methods)))
        plt.tight_layout(rect=[0, 0.08, 1, 0.95])
        outp = os.path.join(out_dir, f"per_dataset_{label}_all_methods_dashboard.png")
        plt.savefig(outp, dpi=180)
        plt.close(fig)

    # 4) Per-dataset per-metric charts: bar + marker for all methods
    for label, df in dataset_frames:
        methods = df.index.tolist()
        palette = ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#14B8A6', '#F97316']
        color_map = {m: palette[i % len(palette)] for i, m in enumerate(methods)}
        for mk, mlabel, scale, is_pct in METRICS:
            vals = []
            colors = []
            for m in methods:
                val = float(df.loc[m][mk]) if mk in df.columns else float('nan')
                vals.append(val * scale if pd.notna(val) else float('nan'))
                colors.append(color_map[m])
            plt.figure(figsize=(10, 6))
            # Bar plot with distinct colors per method
            bars = plt.bar(methods, vals, color=colors, alpha=0.85)
            # Marker overlay matching bar colors
            for i, (m, v) in enumerate(zip(methods, vals)):
                if pd.notna(v):
                    plt.plot(i, v, linestyle='None', marker='D', markersize=7, color=color_map[m])
            plt.title(f'{mlabel} - {label} (all methods)')
            plt.ylabel(f"{mlabel}{' (%)' if is_pct else ''}")
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.3)
            # Value labels
            for i, v in enumerate(vals):
                if pd.notna(v):
                    plt.text(i, v, f"{v:.2f}", ha='center', va='bottom', fontsize=8)
            # Legend mapping colors to methods
            handles = [plt.Line2D([0], [0], marker='s', color=color_map[m], markersize=10, linewidth=0) for m in methods]
            plt.legend(handles, methods, title='Method', bbox_to_anchor=(1.02, 1), loc='upper left', borderaxespad=0.)
            outp = os.path.join(out_dir, f"per_dataset_{label}_{mk}_all_methods.png")
            plt.tight_layout()
            plt.savefig(outp, dpi=170)
            plt.close()

    # 5) All-in-one grouped bar dashboard across datasets
    # Include native percentage metrics AND normalized latency/throughput as percentages
    pct_metrics = [(mk, mlabel, scale, is_pct) for mk, mlabel, scale, is_pct in METRICS if is_pct]
    if dataset_frames and present_methods:
        # Compute global min/max for latency and throughput to normalize to %
        all_latency: List[float] = []
        all_throughput: List[float] = []
        for _, df in dataset_frames:
            for m in present_methods:
                if m in df.index:
                    if 'latency_ms' in df.columns:
                        try:
                            all_latency.append(float(df.loc[m]['latency_ms']))
                        except Exception:
                            pass
                    if 'throughput_rpm' in df.columns:
                        try:
                            all_throughput.append(float(df.loc[m]['throughput_rpm']))
                        except Exception:
                            pass
        lat_min, lat_max = (min(all_latency), max(all_latency)) if all_latency else (0.0, 1.0)
        thr_min, thr_max = (min(all_throughput), max(all_throughput)) if all_throughput else (0.0, 1.0)

        # Build metric spec including normalized latency/throughput
        dashboard_specs = pct_metrics + [
            ('latency_ms_norm_pct', 'Latency (normalized %)', 1.0, True),
            ('throughput_rpm_norm_pct', 'Throughput (normalized %)', 1.0, True),
        ]

        fig, axes = plt.subplots(2, 5, figsize=(26, 10))
        fig.suptitle('Across Datasets — Security Metrics (Grouped Bars)', fontsize=18, fontweight='bold')
        palette = ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#14B8A6', '#F97316']
        method_colors = {m: palette[i % len(palette)] for i, m in enumerate(present_methods)}
        x = list(range(len(x_labels)))
        total_width = 0.8
        bar_width = total_width / max(1, len(present_methods))
        for idx, (mk, mlabel, scale, is_pct) in enumerate(dashboard_specs[:10]):
            r = idx // 5
            c = idx % 5
            ax = axes[r][c]
            # For each method, compute values across datasets
            for mi, method in enumerate(present_methods):
                vals = []
                for _, df in dataset_frames:
                    v_out = float('nan')
                    if method in df.index:
                        if mk == 'latency_ms_norm_pct' and 'latency_ms' in df.columns and lat_max > lat_min:
                            try:
                                v = float(df.loc[method]['latency_ms'])
                                # lower latency -> higher %
                                v_out = (lat_max - v) / (lat_max - lat_min) * 100.0
                            except Exception:
                                v_out = float('nan')
                        elif mk == 'throughput_rpm_norm_pct' and 'throughput_rpm' in df.columns and thr_max > thr_min:
                            try:
                                v = float(df.loc[method]['throughput_rpm'])
                                # higher throughput -> higher %
                                v_out = (v - thr_min) / (thr_max - thr_min) * 100.0
                            except Exception:
                                v_out = float('nan')
                        elif mk in df.columns:
                            try:
                                v = float(df.loc[method][mk])
                                v_out = v * scale
                            except Exception:
                                v_out = float('nan')
                    vals.append(v_out)
                offsets = [xi + (mi - len(present_methods)/2) * bar_width + bar_width/2 for xi in x]
                ax.bar(offsets, vals, width=bar_width, color=method_colors[method], label=method if idx == 0 else None)
            ax.set_title(mlabel, fontweight='bold')
            ax.set_xticks(x)
            ax.set_xticklabels(x_labels)
            ax.set_ylim(0, 105)
            ax.grid(True, linestyle='--', alpha=0.35)
            # value labels
            for container in ax.containers:
                ax.bar_label(container, fmt='%.0f', padding=2, fontsize=8)
        # Shared legend
        handles = [plt.Line2D([0], [0], marker='s', color=method_colors[m], markersize=10, linewidth=0) for m in present_methods]
        fig.legend(handles, present_methods, title='Method', loc='upper center', ncol=min(6, len(present_methods)))
        plt.tight_layout(rect=[0, 0.06, 1, 0.92])
        outp = os.path.join(out_dir, 'across_datasets_grouped_bars_dashboard.png')
        plt.savefig(outp, dpi=180)
        # PDF export for publication
        outp_pdf = os.path.join(out_dir, 'across_datasets_grouped_bars_dashboard.pdf')
        try:
            plt.savefig(outp_pdf)
        except Exception:
            pass
        # SVG export for vector quality
        outp_svg = os.path.join(out_dir, 'across_datasets_grouped_bars_dashboard.svg')
        try:
            plt.savefig(outp_svg)
        except Exception:
            pass
        plt.close(fig)

        # Separate grouped bars for throughput (rpm)
        mk = 'throughput_rpm'
        mlabel = 'Throughput (rpm)'
        plt.figure(figsize=(12, 6))
        for mi, method in enumerate(present_methods):
            vals = []
            for _, df in dataset_frames:
                if method in df.index and mk in df.columns:
                    v = float(df.loc[method][mk])
                    vals.append(v)
                else:
                    vals.append(float('nan'))
            offsets = [xi + (mi - len(present_methods)/2) * bar_width + bar_width/2 for xi in x]
            plt.bar(offsets, vals, width=bar_width, color=method_colors[method], label=method)
        plt.title('Across datasets: Throughput (rpm) (grouped bars)')
        plt.xlabel('Dataset size')
        plt.ylabel('Throughput (rpm)')
        plt.xticks(x, x_labels)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.legend(loc='upper left', ncol=min(6, len(present_methods)))
        outp = os.path.join(out_dir, 'across_datasets_grouped_bars_throughput.png')
        plt.tight_layout()
        plt.savefig(outp, dpi=180)
        # SVG export
        try:
            plt.savefig(os.path.join(out_dir, 'across_datasets_grouped_bars_throughput.svg'))
        except Exception:
            pass
        plt.close()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "results_cross_dataset"
    main(out)


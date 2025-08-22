#!/usr/bin/env python3
"""
Create bar charts comparing methods (ZKP, Regex, LLM, Ensemble) per dataset size
(4k, 6k, 50k, 200k) for core metrics: accuracy, precision, recall, f1.
Also generates grouped bars comparing sizes for each metric across methods.

Usage:
  python tools/aggregate_bars.py --outdir results_bars
"""
import argparse
import csv
import glob
import os
from typing import Dict, List

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

SIZE_ORDER = ['4k', '6k', '50k', '200k']
SIZE_PATTERNS = {
    '4k': [
        'results_official_4k/metrics_*.csv',
        'results_official_4k_figs/metrics_*.csv',
        'results_4k/metrics_*.csv',
        'results_4k_beautiful/metrics_*.csv',
        'results/metrics_*.csv',
        'results_4k_check/metrics_*.csv',
    ],
    '6k': [
        'results_official_6k/metrics_*.csv',
        'results_official_6k_figs*/metrics_*.csv',
    ],
    '50k': [
        'results_official_50k/metrics_*.csv',
        'results_official_50k_figs/metrics_*.csv',
        'results_50k/metrics_*.csv',
    ],
    '200k': [
        'results_200k/metrics_*.csv',
        'results_200k_matplots/metrics_*.csv',
    ],
}
METHODS = ['ZKP Framework', 'Regex Baseline', 'LLM Simulator', 'Ensemble']
METRICS = ['accuracy', 'precision', 'recall', 'f1']
COLORS = ['#667eea', '#764ba2', '#f093fb', '#f5576c']


def pick_latest_csv(patterns: List[str]) -> str:
    candidates: List[str] = []
    for pat in patterns:
        candidates.extend(glob.glob(pat))
    candidates = sorted(candidates, key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0] if candidates else ''


def read_metrics_csv(path: str) -> Dict[str, Dict[str, float]]:
    data: Dict[str, Dict[str, float]] = {}
    if not path:
        return data
    with open(path, 'r', encoding='utf-8') as f:
        rows = [r for r in csv.reader(f) if r]
    if not rows:
        return data
    methods = rows[0][1:]
    for row in rows[1:]:
        if not row:
            continue
        name = row[0] if row[0] else 'metric'
        data[name] = {}
        for m, v in zip(methods, row[1:]):
            try:
                data[name][m] = float(v)
            except Exception:
                pass
    return data


def collect_per_size() -> Dict[str, Dict[str, Dict[str, float]]]:
    # size -> metric -> method -> value
    coll: Dict[str, Dict[str, Dict[str, float]]] = {}
    for s in SIZE_ORDER:
        csv_path = pick_latest_csv(SIZE_PATTERNS.get(s, []))
        data = read_metrics_csv(csv_path)
        if data:
            coll[s] = data
    return coll


def bar_per_size(per_size: Dict[str, Dict[str, Dict[str, float]]], outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    for s in [x for x in SIZE_ORDER if x in per_size]:
        data = per_size[s]
        for metric in METRICS:
            if metric not in data:
                continue
            values = [data[metric].get(m, 0.0) for m in METHODS]
            x = np.arange(len(METHODS))
            plt.figure(figsize=(7, 4))
            bars = plt.bar(x, values, color=COLORS, edgecolor='white')
            plt.xticks(x, METHODS, rotation=20, ha='right')
            plt.ylim(0, 1.0)
            plt.ylabel('Score')
            plt.grid(axis='y', linestyle='--', alpha=0.4)
            for rect, v in zip(bars, values):
                plt.text(rect.get_x() + rect.get_width()/2, rect.get_height() + 0.02,
                         f'{v:.3f}', ha='center', va='bottom', fontsize=9)
            plt.tight_layout()
            plt.savefig(os.path.join(outdir, f'{s}_{metric}_by_method.png'), dpi=200)
            plt.close()


def grouped_by_metric(per_size: Dict[str, Dict[str, Dict[str, float]]], outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    sizes = [x for x in SIZE_ORDER if x in per_size]
    for metric in METRICS:
        # Build matrix: rows=methods, cols=sizes
        mat = []
        for method in METHODS:
            row = []
            for s in sizes:
                row.append(per_size[s].get(metric, {}).get(method, 0.0))
            mat.append(row)
        mat = np.array(mat)

        x = np.arange(len(sizes))
        width = 0.2
        plt.figure(figsize=(9, 5))
        for i, method in enumerate(METHODS):
            plt.bar(x + (i - 1.5) * width, mat[i], width, label=method, color=COLORS[i], edgecolor='white')
        plt.xticks(x, sizes)
        plt.ylim(0, 1.0)
        plt.ylabel('Score')
        plt.grid(axis='y', linestyle='--', alpha=0.4)
        plt.legend()
        for i, method in enumerate(METHODS):
            for xi, v in zip(x, mat[i]):
                plt.text(xi + (i - 1.5) * width, v + 0.02, f'{v:.3f}', ha='center', va='bottom', fontsize=8)
        plt.tight_layout()
        plt.savefig(os.path.join(outdir, f'grouped_{metric}_across_sizes.png'), dpi=200)
        plt.close()


def main():
    parser = argparse.ArgumentParser(description='Generate method comparison bar charts per size and across sizes')
    parser.add_argument('--outdir', required=True)
    args = parser.parse_args()

    per_size = collect_per_size()
    if not per_size:
        raise SystemExit('No metrics found')
    bar_per_size(per_size, args.outdir)
    grouped_by_metric(per_size, args.outdir)


if __name__ == '__main__':
    main()
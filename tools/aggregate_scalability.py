#!/usr/bin/env python3
"""
Aggregate latency/scalability metrics across dataset sizes and produce plots.
Sources metrics CSVs from results folders for sizes: 4k, 6k, 50k, 200k.

Outputs PNGs in a target output directory.

Usage:
  python tools/aggregate_scalability.py --outdir results_scalability
"""
import argparse
import csv
import glob
import os
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Mapping of size label to a list of candidate glob patterns where metrics exist
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


def read_metrics_csv(path: str) -> Dict[str, Dict[str, float]]:
    metrics: Dict[str, Dict[str, float]] = {}
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = [row for row in reader if row]
    if not rows or rows[0][0] != 'metric':
        return metrics
    header = rows[0]
    methods = header[1:]
    for row in rows[1:]:
        mname = row[0]
        metrics[mname] = {}
        for method, v in zip(methods, row[1:]):
            try:
                metrics[mname][method] = float(v)
            except Exception:
                pass
    return metrics


def pick_latest_csv(patterns: List[str]) -> str:
    candidates: List[str] = []
    for pat in patterns:
        candidates.extend(glob.glob(pat))
    # sort by mtime desc
    candidates = sorted(candidates, key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0] if candidates else ''


def collect_avg_latency() -> Dict[str, Dict[str, float]]:
    size_to_latency: Dict[str, Dict[str, float]] = {}
    for size, patterns in SIZE_PATTERNS.items():
        csv_path = pick_latest_csv(patterns)
        if not csv_path:
            continue
        data = read_metrics_csv(csv_path)
        if 'avg_detection_time' in data:
            size_to_latency[size] = data['avg_detection_time']
    return size_to_latency


def plot_latency(size_to_latency: Dict[str, Dict[str, float]], outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    # Sort sizes naturally
    order = [s for s in ['4k', '6k', '50k', '200k'] if s in size_to_latency]

    # For each method, plot avg_detection_time vs size
    for method in METHODS:
        xs = []
        ys_ms = []
        for s in order:
            v = size_to_latency[s].get(method)
            if v is None:
                continue
            xs.append(s)
            ys_ms.append(v * 1000.0)
        if not xs:
            continue
        plt.figure(figsize=(8, 5))
        plt.plot(xs, ys_ms, marker='o', linewidth=2, label=method)
        plt.title(f'Average Detection Time vs Dataset Size - {method}')
        plt.xlabel('Dataset Size')
        plt.ylabel('Latency (ms per prompt)')
        plt.grid(True, linestyle='--', alpha=0.4)
        plt.tight_layout()
        plt.savefig(os.path.join(outdir, f'latency_vs_size_{method.replace(" ", "_")}.png'), dpi=200)
        plt.close()

    # Combined plot
    plt.figure(figsize=(9, 6))
    for method in METHODS:
        xs = []
        ys_ms = []
        for s in order:
            v = size_to_latency[s].get(method)
            if v is None:
                continue
            xs.append(s)
            ys_ms.append(v * 1000.0)
        if xs:
            plt.plot(xs, ys_ms, marker='o', linewidth=2, label=method)
    plt.title('Average Detection Time vs Dataset Size (All Methods)')
    plt.xlabel('Dataset Size')
    plt.ylabel('Latency (ms per prompt)')
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, 'latency_vs_size_all_methods.png'), dpi=200)
    plt.close()

    # Throughput based on latency (items/sec)
    plt.figure(figsize=(9, 6))
    for method in METHODS:
        xs = []
        thr = []
        for s in order:
            v = size_to_latency[s].get(method)
            if v is None or v <= 0:
                continue
            xs.append(s)
            thr.append(1.0 / v)
        if xs:
            plt.plot(xs, thr, marker='o', linewidth=2, label=method)
    plt.title('Throughput vs Dataset Size (items/sec)')
    plt.xlabel('Dataset Size')
    plt.ylabel('Throughput (items/sec)')
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, 'throughput_vs_size_all_methods.png'), dpi=200)
    plt.close()

    # Estimated total time = latency * N (seconds)
    size_to_count = {'4k': 4000, '6k': 6000, '50k': 50000, '200k': 200000}
    plt.figure(figsize=(9, 6))
    for method in METHODS:
        xs = []
        totals = []
        for s in order:
            v = size_to_latency[s].get(method)
            if v is None:
                continue
            xs.append(s)
            totals.append(v * size_to_count[s])
        if xs:
            plt.plot(xs, totals, marker='o', linewidth=2, label=method)
    plt.title('Estimated Total Evaluation Time vs Dataset Size')
    plt.xlabel('Dataset Size')
    plt.ylabel('Total Time (seconds)')
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, 'total_time_vs_size_all_methods.png'), dpi=200)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description='Aggregate scalability metrics and plot')
    parser.add_argument('--outdir', required=True)
    args = parser.parse_args()

    size_to_latency = collect_avg_latency()
    if not size_to_latency:
        raise SystemExit('No metrics found to aggregate')

    plot_latency(size_to_latency, args.outdir)

    # Write a summary CSV of latency in ms per size/method
    os.makedirs(args.outdir, exist_ok=True)
    out_csv = os.path.join(args.outdir, 'latency_summary_ms.csv')
    sizes = [s for s in ['4k', '6k', '50k', '200k'] if s in size_to_latency]
    with open(out_csv, 'w', encoding='utf-8') as f:
        f.write('size,' + ','.join(METHODS) + '\n')
        for s in sizes:
            row = [s]
            for method in METHODS:
                v = size_to_latency[s].get(method, '')
                row.append(str(v * 1000.0) if v != '' else '')
            f.write(','.join(row) + '\n')


if __name__ == '__main__':
    main()
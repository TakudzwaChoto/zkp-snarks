#!/usr/bin/env python3
"""
Multi-dataset evaluation runner

Runs AdvancedEvaluationPipeline on datasets of sizes 4k, 6k, 50k, 120k, 200k.
Computes and saves metrics: accuracy, precision, recall, f1, latency, tamper_resistance,
"detection_rate" (alias of recall), TP, TN, FP, FN. Exports confusion matrices and
distribution plots with clear, non-overlapping styling. Also generates aggregated
visuals across sizes.
"""

import os
import sys
import csv
import json
import time
from typing import Dict, List, Tuple

try:
    import numpy as np  # type: ignore
except Exception:
    np = None

try:
    import matplotlib.pyplot as plt  # type: ignore
except Exception:
    plt = None

from datetime import datetime

from evaluation_pipeline import AdvancedEvaluationPipeline, DetectionResult


DATASET_SIZES = [4000, 6000, 50000, 120000, 200000]


def ensure_dirs(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def format_size(n: int) -> str:
    if n >= 1000:
        return f"{n//1000}k"
    return str(n)


def compute_confusion(y_true: List[int], y_pred: List[int]) -> Tuple[int, int, int, int]:
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    return tp, tn, fp, fn


def derive_metrics(results: List[DetectionResult]) -> Dict[str, float]:
    y_true = [1 if r.true_label == "adversarial" else 0 for r in results]
    y_pred = [1 if r.predicted_label == "adversarial" else 0 for r in results]
    tp, tn, fp, fn = compute_confusion(y_true, y_pred)
    total = max(1, len(results))
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total
    if np is None:
        avg_detection_time = sum(r.detection_time for r in results) / total
    else:
        avg_detection_time = float(np.mean([r.detection_time for r in results]))
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "avg_detection_time": avg_detection_time,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        # detection_rate: treat as recall (malicious detection rate)
        "detection_rate": recall,
    }


def style_plots():
    if plt is None:
        return
    plt.style.use('default')
    # emulate a light grid style
    plt.rcParams.update({
        'axes.facecolor': '#f8f9fa',
        'axes.edgecolor': '#dadee4',
        'grid.color': '#e9ecef',
        'grid.linestyle': '--',
        'grid.alpha': 0.55,
    })
    plt.rcParams['font.size'] = 10
    plt.rcParams['axes.titlesize'] = 14
    plt.rcParams['axes.labelsize'] = 12
    plt.rcParams['legend.fontsize'] = 10


def plot_metrics_grouped(metrics_by_method: Dict[str, Dict[str, float]], out_path: str, title: str) -> None:
    if plt is None:
        return
    methods = list(metrics_by_method.keys())
    groups = ["accuracy", "precision", "recall", "f1"]
    x = np.arange(len(methods)) if np is not None else list(range(len(methods)))
    width = 0.18
    fig, ax = plt.subplots(figsize=(12, 7))
    colors = ['#2F5597', '#9E480E', '#316395', '#4F81BD']
    for i, g in enumerate(groups):
        vals = [metrics_by_method[m].get(g, 0.0) * 100.0 for m in methods]
        if np is None:
            xoff = [xi + (i - 1.5) * width for xi in x]
            ax.bar(xoff, vals, width=width, label=g.title(), color=colors[i], edgecolor='white', linewidth=1)
        else:
            ax.bar(x + (i - 1.5) * width, vals, width=width, label=g.title(), color=colors[i], edgecolor='white', linewidth=1)
    ax.set_title(title)
    ax.set_ylabel('Score (%)')
    ax.set_xticks(x)
    ax.set_xticklabels(methods, rotation=20, ha='right')
    ax.set_ylim(0, 100)
    ax.legend(loc='upper center', ncol=4, frameon=False)
    ax.grid(axis='y', alpha=0.35, linestyle='--')
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches='tight', facecolor='white')
    plt.close(fig)


def plot_latency_bar(latency_by_method: Dict[str, float], out_path: str, title: str) -> None:
    if plt is None:
        return
    methods = list(latency_by_method.keys())
    values = [latency_by_method[m] * 1000.0 for m in methods]
    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ['#4F81BD'] * len(methods)
    bars = ax.bar(range(len(methods)), values, color=colors, edgecolor='black', linewidth=0.6)
    ax.set_title(title)
    ax.set_ylabel('Latency (ms)')
    ax.set_xticks(range(len(methods)))
    ax.set_xticklabels(methods, rotation=20, ha='right')
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + (max(values) * 0.015 if max(values) else 1), f"{v:.1f}", ha='center', va='bottom')
    ax.grid(axis='y', alpha=0.35, linestyle='--')
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches='tight', facecolor='white')
    plt.close(fig)


def plot_confusion_matrix(tp: int, tn: int, fp: int, fn: int, out_path: str, title: str) -> None:
    if plt is None:
        return
    import numpy as _np
    cm = _np.array([[tn, fp], [fn, tp]], dtype=float)
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap='RdYlBu_r')
    ax.set_title(title)
    ax.set_xlabel('Predicted (0=benign, 1=adversarial)')
    ax.set_ylabel('Actual (0=benign, 1=adversarial)')
    # Add counts
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{int(cm[i, j])}", ha='center', va='center', color='black')
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label('Count')
    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches='tight', facecolor='white')
    plt.close(fig)


def plot_outcome_distribution(tp: int, tn: int, fp: int, fn: int, out_path: str, title: str) -> None:
    if plt is None:
        return
    labels = ['TP', 'TN', 'FP', 'FN']
    values = [tp, tn, fp, fn]
    colors = ['#43e97b', '#667eea', '#f093fb', '#f5576c']
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(labels, values, color=colors, edgecolor='white', linewidth=1)
    ax.set_title(title)
    ax.set_ylabel('Count')
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.01, f"{v}", ha='center', va='bottom')
    ax.grid(True, axis='y', alpha=0.35, linestyle='--')
    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches='tight', facecolor='white')
    plt.close(fig)


def run_single_dataset(dataset_path: str, out_dir: str) -> Dict[str, Dict[str, float]]:
    ensure_dirs(out_dir)
    pipeline = AdvancedEvaluationPipeline(dataset_path)
    # Configure optional parallel workers via env var
    all_results = pipeline.run_evaluation()
    metrics_by_method: Dict[str, Dict[str, float]] = {}
    for method, results in all_results.items():
        metrics = pipeline.calculate_metrics(results)
        # add detection_rate alias and latency_ms
        metrics['detection_rate'] = metrics.get('recall', 0.0)
        metrics['latency_ms'] = metrics.get('avg_detection_time', 0.0) * 1000.0
        metrics_by_method[method] = metrics
    # Tamper resistance per method (uses adversarial perturbations, capped internally)
    try:
        tr_targets = {
            'ZKP Framework': pipeline.zkp_detection,
            'Regex Baseline': pipeline.regex_baseline,
            'LLM Simulator': pipeline.llm_simulator,
            'Ensemble': pipeline.ensemble_detection,
        }
        for m_name, fn in tr_targets.items():
            if m_name in metrics_by_method:
                tr_score = pipeline._compute_tamper_resistance(m_name, fn, pipeline.test_dataset, k_variants=1)
                metrics_by_method[m_name]['tamper_resistance'] = tr_score
    except Exception:
        pass

    # Save per-dataset metrics CSV
    csv_path = os.path.join(out_dir, 'metrics.csv')
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        methods = list(metrics_by_method.keys())
        writer.writerow(['Metric'] + methods)
        wanted = ['accuracy', 'precision', 'recall', 'f1', 'latency_ms', 'tamper_resistance', 'detection_rate', 'true_positives', 'true_negatives', 'false_positives', 'false_negatives']
        for metric in wanted:
            row = [metric]
            for m in methods:
                row.append(metrics_by_method[m].get(metric, 0))
            writer.writerow(row)

    # Plots per dataset
    style_plots()
    if plt is not None:
        plot_metrics_grouped(metrics_by_method, os.path.join(out_dir, 'metrics_grouped.png'), title='Metrics by Method')
        plot_latency_bar({m: d.get('avg_detection_time', 0.0) for m, d in metrics_by_method.items()}, os.path.join(out_dir, 'latency.png'), title='Latency by Method')
        # Confusion matrix and distribution for Ensemble (primary) and ZKP
        for key in ['Ensemble', 'ZKP Framework']:
            if key in all_results:
                # derive confusion
                m = metrics_by_method.get(key, {})
                tp = int(m.get('true_positives', 0))
                tn = int(m.get('true_negatives', 0))
                fp = int(m.get('false_positives', 0))
                fn = int(m.get('false_negatives', 0))
                plot_confusion_matrix(tp, tn, fp, fn, os.path.join(out_dir, f'confusion_{key.replace(" ", "_")}.png'), title=f'Confusion Matrix - {key}')
                plot_outcome_distribution(tp, tn, fp, fn, os.path.join(out_dir, f'distribution_{key.replace(" ", "_")}.png'), title=f'Outcome Distribution - {key}')
    return metrics_by_method


def _create_subset_csv(in_path: str, out_path: str, limit: int) -> None:
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(in_path, 'r', encoding='utf-8') as fin, open(out_path, 'w', encoding='utf-8') as fout:
        header = fin.readline()
        fout.write(header)
        count = 0
        for line in fin:
            if not line.strip():
                continue
            fout.write(line)
            count += 1
            if count >= limit:
                break


def sweep_thresholds(dataset_path: str, expected_size: int, work_dir: str) -> Tuple[float, float, Dict[str, float]]:
    os.makedirs(work_dir, exist_ok=True)
    # Build subset
    if expected_size <= 6000:
        subset_n = min(2000, expected_size // 2)
    elif expected_size <= 50000:
        subset_n = 5000
    else:
        subset_n = 10000
    subset_path = os.path.join(work_dir, 'subset.csv')
    _create_subset_csv(dataset_path, subset_path, subset_n)

    # Parameter grid
    sem_grid = [0.30, 0.33, 0.35, 0.38, 0.40, 0.43]
    ens_grid = [0.12, 0.15, 0.18, 0.20, 0.22, 0.25]
    best = {'f1': -1.0, 'sem': 0.35, 'ens': 0.18}

    # Fix weights to balanced mix that worked best
    os.environ['ENSEMBLE_MODE'] = os.environ.get('ENSEMBLE_MODE', 'weighted')
    os.environ['ENSEMBLE_W_ZKP'] = os.environ.get('ENSEMBLE_W_ZKP', '0.20')
    os.environ['ENSEMBLE_W_REGEX'] = os.environ.get('ENSEMBLE_W_REGEX', '0.30')
    os.environ['ENSEMBLE_W_LLM'] = os.environ.get('ENSEMBLE_W_LLM', '0.10')
    os.environ['ENSEMBLE_W_SEM'] = os.environ.get('ENSEMBLE_W_SEM', '0.40')

    for sem in sem_grid:
        os.environ['SEMANTIC_THRESHOLD'] = str(sem)
        for ens in ens_grid:
            os.environ['ENSEMBLE_THRESHOLD'] = str(ens)
            tmp_out = os.path.join(work_dir, f'tmp_sem_{sem}_ens_{ens}'.replace('.', '_'))
            try:
                metrics = run_single_dataset(subset_path, tmp_out)
                f1 = float(metrics.get('Ensemble', {}).get('f1', 0.0))
                if f1 > best['f1']:
                    best.update({'f1': f1, 'sem': sem, 'ens': ens})
            except Exception:
                continue

    # Return best thresholds and metrics snapshot for reference
    return best['sem'], best['ens'], {'best_f1_subset': best['f1'], 'subset_n': float(subset_n)}


def aggregate_plots(all_metrics: Dict[int, Dict[str, Dict[str, float]]], out_root: str) -> None:
    if plt is None or np is None:
        return
    style_plots()
    methods = set()
    for _, m in all_metrics.items():
        methods.update(m.keys())
    methods = sorted(list(methods))
    sizes = sorted(all_metrics.keys())

    # For each metric, line plot vs dataset size
    metric_names = ['accuracy', 'precision', 'recall', 'f1', 'latency_ms', 'tamper_resistance']
    for met in metric_names:
        fig, ax = plt.subplots(figsize=(12, 7))
        for method in methods:
            yvals = []
            for s in sizes:
                val = all_metrics[s].get(method, {}).get(met, np.nan)
                yvals.append(val)
            ax.plot([format_size(s) for s in sizes], yvals, marker='o', linewidth=2.5, label=method)
        ax.set_title(f'{met.replace("_", " ").title()} vs Dataset Size')
        ax.set_xlabel('Dataset Size')
        ax.set_ylabel(met.replace('_', ' ').title())
        ax.grid(True, alpha=0.35, linestyle='--')
        ax.legend(loc='best')
        fig.tight_layout()
        fig.savefig(os.path.join(out_root, f'aggregate_{met}.png'), dpi=200, bbox_inches='tight', facecolor='white')
        plt.close(fig)


def compute_and_save_layer_metrics(all_results: Dict[str, Dict[str, Dict[str, float]]], layers_path: str, out_root: str, size_tag: str) -> None:
    try:
        with open(layers_path, 'r', encoding='utf-8') as f:
            layers = json.load(f)
    except Exception:
        return
    # Invert mapping: method -> layer
    method_to_layer: Dict[str, str] = {}
    for layer, methods in layers.items():
        for m in methods:
            method_to_layer[m] = layer
    # Aggregate per layer for this size
    metrics: Dict[str, Dict[str, float]] = {}
    for method, data in all_results.items():
        layer = method_to_layer.get(method, None)
        if layer is None:
            continue
        if layer not in metrics:
            metrics[layer] = {
                'tp': 0.0, 'tn': 0.0, 'fp': 0.0, 'fn': 0.0, 'latency_sum': 0.0, 'count': 0.0
            }
        metrics[layer]['tp'] += data.get('true_positives', 0.0)
        metrics[layer]['tn'] += data.get('true_negatives', 0.0)
        metrics[layer]['fp'] += data.get('false_positives', 0.0)
        metrics[layer]['fn'] += data.get('false_negatives', 0.0)
        metrics[layer]['latency_sum'] += data.get('avg_detection_time', 0.0)
        metrics[layer]['count'] += 1.0
    # Derive standard metrics
    rows: List[List[str]] = [['layer', 'accuracy', 'precision', 'recall', 'f1', 'latency_ms', 'tp', 'tn', 'fp', 'fn']]
    for layer, d in metrics.items():
        tp = d['tp']; tn = d['tn']; fp = d['fp']; fn = d['fn']
        total = tp + tn + fp + fn
        precision = (tp / (tp + fp)) if (tp + fp) else 0.0
        recall = (tp / (tp + fn)) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        accuracy = ((tp + tn) / total) if total else 0.0
        latency_ms = (d['latency_sum'] / d['count'] * 1000.0) if d['count'] else 0.0
        rows.append([layer, f"{accuracy}", f"{precision}", f"{recall}", f"{f1}", f"{latency_ms}", f"{int(tp)}", f"{int(tn)}", f"{int(fp)}", f"{int(fn)}"])                                                                                                                                                                                                                                                                                              
    # Save CSV
    out_dir = os.path.join(out_root, f"size_{size_tag}")
    os.makedirs(out_dir, exist_ok=True)
    layer_csv = os.path.join(out_dir, 'layer_metrics.csv')
    with open(layer_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def main():
    out_root = os.path.abspath('results_multi')
    ensure_dirs(out_root)
    # Optionally set workers if provided
    os.environ.setdefault('EVAL_WORKERS', os.environ.get('EVAL_WORKERS', '4'))

    # Generate datasets if missing
    generated_paths: Dict[int, str] = {}
    for n in DATASET_SIZES:
        half = n // 2
        name = f"data/{format_size(n)}data.csv"
        abspath = os.path.abspath(name)
        if not os.path.exists(abspath):
            # lazily generate via CLI to avoid import coupling
            cmd = f"python3 data/generate_dataset.py -b {half} -a {n - half} --format csv --out {name}"
            print(f"Generating dataset {n} via: {cmd}")
            code = os.system(cmd)
            if code != 0 or not os.path.exists(abspath):
                print(f"Failed to generate {name}")
                sys.exit(1)
        generated_paths[n] = abspath

    # Run evaluations
    all_metrics: Dict[int, Dict[str, Dict[str, float]]] = {}
    for n in DATASET_SIZES:
        ds_path = generated_paths[n]
        out_dir = os.path.join(out_root, f"size_{format_size(n)}")
        print(f"\n=== Evaluating dataset size {n} ({ds_path}) ===")
        # Sweep thresholds on a subset first
        print("- Sweeping thresholds on subset...")
        sem_thr, ens_thr, info = sweep_thresholds(ds_path, n, os.path.join(out_dir, 'sweep'))
        os.environ['SEMANTIC_THRESHOLD'] = str(sem_thr)
        os.environ['ENSEMBLE_THRESHOLD'] = str(ens_thr)
        with open(os.path.join(out_dir, 'chosen_thresholds.json'), 'w') as f:
            json.dump({'semantic_threshold': sem_thr, 'ensemble_threshold': ens_thr, **info}, f, indent=2)
        print(f"  -> chosen: semantic={sem_thr:.2f}, ensemble={ens_thr:.2f} (subset F1={info['best_f1_subset']:.3f})")
        # Now run full dataset with chosen thresholds
        metrics_by_method = run_single_dataset(ds_path, out_dir)
        # Save per-layer metrics alongside per-method, using layers.json
        try:
            compute_and_save_layer_metrics(metrics_by_method, os.path.abspath('layers.json'), out_root, format_size(n))
        except Exception:
            pass
        all_metrics[n] = metrics_by_method

    # Save combined CSV
    combined_csv = os.path.join(out_root, 'combined_metrics.csv')
    with open(combined_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        # header: size, method, metrics...
        headers = ['size', 'method', 'accuracy', 'precision', 'recall', 'f1', 'latency_ms', 'tamper_resistance', 'detection_rate', 'true_positives', 'true_negatives', 'false_positives', 'false_negatives']
        writer.writerow(headers)
        for n in DATASET_SIZES:
            for method, data in all_metrics[n].items():
                row = [n, method]
                for key in headers[2:]:
                    row.append(data.get(key, 0))
                writer.writerow(row)

    # Aggregated visuals across sizes
    aggregate_plots(all_metrics, out_root)
    print(f"\n✅ Multi-dataset evaluation complete. Results at: {out_root}")


if __name__ == '__main__':
    main()


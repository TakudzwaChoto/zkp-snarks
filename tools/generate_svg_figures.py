#!/usr/bin/env python3
"""
Generate SVG figures from evaluation metrics CSV without external dependencies.
Produces separate bar charts for accuracy, precision, recall, f1, and latency (ms).

Usage:
  python tools/generate_svg_figures.py --metrics_csv /path/to/metrics.csv --outdir /path/to/out
"""
import argparse
import csv
import math
import os
from typing import Dict, List, Tuple

SVG_HEADER = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'


def read_metrics_csv(path: str) -> Tuple[List[str], Dict[str, Dict[str, float]]]:
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = [row for row in reader if row]
    if not rows:
        raise ValueError("Empty metrics CSV")
    header = rows[0]
    if len(header) < 2 or header[0] != 'metric':
        raise ValueError("Invalid CSV header; expected first column 'metric'")
    methods = header[1:]
    metrics: Dict[str, Dict[str, float]] = {}
    for row in rows[1:]:
        metric_name = row[0]
        values: Dict[str, float] = {}
        for method, value_str in zip(methods, row[1:]):
            try:
                values[method] = float(value_str)
            except Exception:
                # allow blanks
                continue
        metrics[metric_name] = values
    return methods, metrics


def _escape(text: str) -> str:
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;'))


def draw_bar_chart(methods: List[str], values: Dict[str, float], *, title: str,
                   y_label: str, out_path: str, y_min: float = 0.0,
                   y_max: float = None, value_fmt: str = '{:.3f}',
                   height: int = 520, width: int = 860) -> None:
    # Layout
    margin_left = 90
    margin_right = 30
    margin_top = 60
    margin_bottom = 120
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom

    # Determine y scale
    vals = [values.get(m, 0.0) for m in methods]
    max_val = max(vals) if vals else 1.0
    if y_max is None:
        y_max = max_val * 1.05 if max_val > 0 else 1.0
        if y_label.lower().startswith('score') or title.lower().startswith('accuracy') or title.lower().startswith('precision') or title.lower().startswith('recall') or title.lower().startswith('f1'):
            y_max = max(1.0, y_max)
    # y to pixel
    def y_to_px(v: float) -> float:
        if y_max == y_min:
            return margin_top + plot_h
        return margin_top + plot_h - (v - y_min) / (y_max - y_min) * plot_h

    # x positions
    n = len(methods)
    bar_w = plot_w / max(1, n) * 0.6
    gap = (plot_w - n * bar_w) / max(1, n + 1)
    xs = [margin_left + gap + i * (bar_w + gap) for i in range(n)]

    # Colors (pleasant palette)
    colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#45B7D1', '#43e97b', '#38f9d7', '#FF6B6B']

    # Build SVG content
    parts: List[str] = []
    parts.append(SVG_HEADER)
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    # Background
    parts.append('<rect x="0" y="0" width="100%" height="100%" fill="#ffffff"/>')

    # Title
    parts.append(f'<text x="{width/2}" y="{margin_top-20}" text-anchor="middle" font-family="sans-serif" font-size="20" font-weight="bold" fill="#2c3e50">{_escape(title)}</text>')

    # Axes
    # y-axis line
    parts.append(f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top+plot_h}" stroke="#95a5a6" stroke-width="1"/>')
    # x-axis line
    parts.append(f'<line x1="{margin_left}" y1="{margin_top+plot_h}" x2="{margin_left+plot_w}" y2="{margin_top+plot_h}" stroke="#95a5a6" stroke-width="1"/>')

    # Grid lines and y ticks (5 ticks)
    ticks = 5
    for i in range(ticks + 1):
        y_val = y_min + (y_max - y_min) * i / ticks
        y_px = y_to_px(y_val)
        parts.append(f'<line x1="{margin_left}" y1="{y_px}" x2="{margin_left+plot_w}" y2="{y_px}" stroke="#ecf0f1" stroke-width="1"/>')
        parts.append(f'<text x="{margin_left-10}" y="{y_px+4}" text-anchor="end" font-family="sans-serif" font-size="12" fill="#2c3e50">{value_fmt.format(y_val)}</text>')

    # y label
    parts.append(f'<text x="{margin_left-60}" y="{margin_top + plot_h/2}" transform="rotate(-90 {margin_left-60},{margin_top + plot_h/2})" text-anchor="middle" font-family="sans-serif" font-size="12" font-weight="bold" fill="#2c3e50">{_escape(y_label)}</text>')

    # Bars
    for i, method in enumerate(methods):
        v = values.get(method, 0.0)
        x = xs[i]
        y = y_to_px(max(v, y_min))
        h = (margin_top + plot_h) - y
        color = colors[i % len(colors)]
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
        # Value label
        label = value_fmt.format(v)
        parts.append(f'<text x="{x + bar_w/2}" y="{y - 6}" text-anchor="middle" font-family="sans-serif" font-size="12" font-weight="bold" fill="#2c3e50">{label}</text>')
        # X label (rotated)
        lx = x + bar_w/2
        ly = margin_top + plot_h + 14
        parts.append(f'<text x="{lx}" y="{ly}" transform="rotate(-30 {lx},{ly})" text-anchor="end" font-family="sans-serif" font-size="12" fill="#2c3e50">{_escape(method)}</text>')

    parts.append('</svg>')

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))


def main():
    parser = argparse.ArgumentParser(description='Generate SVG charts from metrics CSV')
    parser.add_argument('--metrics_csv', required=True)
    parser.add_argument('--outdir', required=True)
    args = parser.parse_args()

    methods, metrics = read_metrics_csv(args.metrics_csv)

    # Core score charts (0..1)
    charts = [
        ('accuracy', 'Accuracy', 'Score'),
        ('precision', 'Precision', 'Score'),
        ('recall', 'Recall', 'Score'),
        ('f1', 'F1 Score', 'Score'),
        ('specificity', 'Specificity', 'Score'),
        ('sensitivity', 'Sensitivity', 'Score'),
    ]
    for key, title, y_label in charts:
        if key in metrics:
            out_path = os.path.join(args.outdir, f'{key}_bar.svg')
            draw_bar_chart(methods, metrics[key], title=title, y_label=y_label,
                           out_path=out_path, y_min=0.0, y_max=1.0,
                           value_fmt='{:.3f}')

    # Latency chart (convert seconds to ms)
    if 'avg_detection_time' in metrics:
        ms_values = {m: metrics['avg_detection_time'].get(m, 0.0) * 1000.0 for m in methods}
        max_ms = max(ms_values.values()) if ms_values else 1.0
        # Round up max_y to a neat value
        magnitude = 10 ** int(math.floor(math.log10(max_ms))) if max_ms > 0 else 1
        neat_max = math.ceil(max_ms / magnitude) * magnitude
        out_path = os.path.join(args.outdir, 'latency_ms_bar.svg')
        draw_bar_chart(methods, ms_values, title='Average Detection Time', y_label='Milliseconds (ms)',
                       out_path=out_path, y_min=0.0, y_max=neat_max,
                       value_fmt='{:.3f}')

    # Confusion components (optional absolute counts)
    extra = ['true_positives', 'true_negatives', 'false_positives', 'false_negatives']
    for key in extra:
        if key in metrics:
            # values may be floats in CSV; treat as numeric
            vals = {m: metrics[key].get(m, 0.0) for m in methods}
            max_v = max(vals.values()) if vals else 1.0
            out_path = os.path.join(args.outdir, f'{key}_bar.svg')
            draw_bar_chart(methods, vals, title=key.replace('_', ' ').title(), y_label='Count',
                           out_path=out_path, y_min=0.0, y_max=max_v * 1.05,
                           value_fmt='{:.0f}')


if __name__ == '__main__':
    main()
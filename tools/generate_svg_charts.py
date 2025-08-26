#!/usr/bin/env python3
"""
Generate SVG visualizations from existing evaluation results without external libs.
Reads:
- results_comprehensive_renamed/all_datasets_comparison_renamed.csv (4k, 6k, 50k, 200k)
- results_comprehensive_renamed/120k_kaggle_evaluation_*.json (latest)
- results_anticollusion/anticollusion_metrics_*.json (latest aggregate)
- results_anticollusion/test_*_*.json (per-size anti-collusion snapshots if present)

Outputs SVGs into results_visualizations_complete/:
- svg_performance_bars.svg (Detection/FPR/Tamper for all sizes)
- svg_latency_throughput.svg (Latency and Throughput bars)
- svg_anticollusion_summary.svg (Aggregate anti-collusion metrics)
"""

import os
import csv
import json
import glob
from typing import Dict, List, Tuple, Optional

OUTPUT_DIR = 'results_visualizations_complete'
COMP_PATH = 'results_comprehensive_renamed/all_datasets_comparison_renamed.csv'
COMP_DIR = 'results_comprehensive_renamed'
ANTI_DIR = 'results_anticollusion'


def ensure_output_dir() -> None:
	os.makedirs(OUTPUT_DIR, exist_ok=True)


def read_comprehensive_csv(path: str) -> Dict[str, Dict[str, float]]:
	results: Dict[str, Dict[str, float]] = {}
	if not os.path.exists(path):
		return results
	with open(path, 'r', encoding='utf-8') as f:
		r = csv.DictReader(f)
		for row in r:
			name = row.get('dataset_name', '').strip()
			if not name:
				continue
			results[name] = {
				'collusion_detection_rate': float(row.get('collusion_detection_rate', '0') or 0),
				'false_positive_rate': float(row.get('false_positive_rate', '0') or 0),
				'tamper_resistance': float(row.get('tamper_resistance', '0') or 0),
				'latency_ms': float(row.get('latency_ms', '0') or 0),
				'throughput_rpm': float(row.get('throughput_rpm', '0') or 0),
			}
	return results


def read_latest_120k_json(comp_dir: str) -> Optional[Dict[str, float]]:
	files = sorted(glob.glob(os.path.join(comp_dir, '120k_kaggle_evaluation_*.json')))
	if not files:
		return None
	latest = files[-1]
	with open(latest, 'r', encoding='utf-8') as f:
		return json.load(f)


def read_latest_anticollusion_json(anti_dir: str) -> Optional[Dict[str, float]]:
	files = sorted(glob.glob(os.path.join(anti_dir, 'anticollusion_metrics_*.json')))
	if not files:
		return None
	with open(files[-1], 'r', encoding='utf-8') as f:
		return json.load(f)


def read_per_size_anticollusion(anti_dir: str) -> Dict[str, Dict[str, float]]:
	out: Dict[str, Dict[str, float]] = {}
	for size in ['4k', '6k', '50k', '120k', '200k']:
		files = sorted(glob.glob(os.path.join(anti_dir, f'test_{size}_*.json')))
		if not files:
			continue
		with open(files[-1], 'r', encoding='utf-8') as f:
			out[size] = json.load(f)
	return out


# --- Minimal SVG helpers ---

def svg_rect(x: float, y: float, w: float, h: float, fill: str = '#4e79a7') -> str:
	return f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" fill="{fill}" />'


def svg_text(x: float, y: float, text: str, size: int = 12, anchor: str = 'middle', weight: str = 'normal') -> str:
	return f'<text x="{x:.2f}" y="{y:.2f}" font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" font-family="Inter, Arial, sans-serif">{text}</text>'


def svg_line(x1: float, y1: float, x2: float, y2: float, stroke: str = '#ccc', width: float = 1.0) -> str:
	return f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" stroke="{stroke}" stroke-width="{width:.2f}" />'


def scale_values(values: List[float], max_height: float) -> List[float]:
	max_val = max(values) if values else 1.0
	if max_val == 0:
		max_val = 1.0
	return [(v / max_val) * max_height for v in values]


def write_svg(filename: str, width: int, height: int, content: List[str]) -> None:
	svg = [
		f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
		'<rect x="0" y="0" width="100%" height="100%" fill="#ffffff" />'
	]
	svg.extend(content)
	svg.append('</svg>')
	with open(os.path.join(OUTPUT_DIR, filename), 'w', encoding='utf-8') as f:
		f.write('\n'.join(svg))


# --- Chart builders ---

def build_performance_bars(all_results: Dict[str, Dict[str, float]], metrics: List[str], title: str, filename: str) -> None:
	# Order sizes nicely
	labels_map = {
		'4k_curated': '4k',
		'6k_kaggle': '6k',
		'50k_curated': '50k',
		'120k_kaggle': '120k',
		'200k_curated': '200k',
	}
	ordered_keys = [k for k in ['4k_curated', '6k_kaggle', '50k_curated', '120k_kaggle', '200k_curated'] if k in all_results]
	labels = [labels_map[k] for k in ordered_keys]
	width = 900
	height = 420
	pad = 60
	bar_group_w = (width - 2 * pad) / max(1, len(labels))
	bar_w = bar_group_w / (len(metrics) + 1)
	max_height = height - 2 * pad
	content: List[str] = []
	content.append(svg_text(width / 2, 30, title, size=18, weight='bold'))
	# Grid lines
	for i in range(6):
		y = pad + (i * (max_height / 5))
		content.append(svg_line(pad, y, width - pad, y, '#eee', 1))
	# Bars
	palette = ['#4e79a7', '#f28e2b', '#59a14f']
	for mi, metric in enumerate(metrics):
		values = [all_results[k].get(metric, 0.0) for k in ordered_keys]
		# If metric is rate, keep as 0..1
		scaled = scale_values(values, max_height)
		for i, val in enumerate(scaled):
			x = pad + i * bar_group_w + mi * bar_w
			y = pad + (max_height - val)
			content.append(svg_rect(x, y, bar_w * 0.9, val, fill=palette[mi % len(palette)]))
			# Value label
			text_val = f"{values[i]*100:.1f}%" if 'rate' in metric or 'resistance' in metric else f"{values[i]:.2f}"
			content.append(svg_text(x + bar_w * 0.45, y - 6, text_val, size=11))
	# X labels and legend
	for i, lbl in enumerate(labels):
		x = pad + i * bar_group_w + (len(metrics) * bar_w) / 2
		content.append(svg_text(x, height - pad + 20, lbl, size=12))
	legend_x = width - pad - 220
	legend_y = pad - 30
	for mi, metric in enumerate(metrics):
		content.append(svg_rect(legend_x + mi * 70, legend_y, 14, 14, fill=palette[mi % len(palette)]))
		content.append(svg_text(legend_x + mi * 70 + 20, legend_y + 12, metric.replace('_', ' ').title(), size=12, anchor='start'))
	write_svg(filename, width, height, content)


def build_latency_throughput_bars(all_results: Dict[str, Dict[str, float]], filename: str) -> None:
	labels_map = {
		'4k_curated': '4k',
		'6k_kaggle': '6k',
		'50k_curated': '50k',
		'120k_kaggle': '120k',
		'200k_curated': '200k',
	}
	ordered_keys = [k for k in ['4k_curated', '6k_kaggle', '50k_curated', '120k_kaggle', '200k_curated'] if k in all_results]
	labels = [labels_map[k] for k in ordered_keys]
	width = 900
	height = 440
	pad = 60
	content: List[str] = []
	content.append(svg_text(width / 2, 30, 'Latency and Throughput by Dataset Size', size=18, weight='bold'))
	# Latency panel (left)
	panel_w = (width - 3 * pad) / 2
	panel_h = height - 2 * pad
	bar_w = (panel_w - 20) / max(1, len(labels))
	latencies = [all_results[k].get('latency_ms', 0.0) for k in ordered_keys]
	lat_scaled = scale_values(latencies, panel_h)
	# Grid
	for i in range(6):
		y = pad + (i * (panel_h / 5))
		content.append(svg_line(pad, y, pad + panel_w, y, '#eee', 1))
	for i, val in enumerate(lat_scaled):
		x = pad + i * bar_w
		y = pad + (panel_h - val)
		content.append(svg_rect(x, y, bar_w * 0.8, val, fill='#4e79a7'))
		content.append(svg_text(x + bar_w * 0.4, y - 6, f"{latencies[i]:.2f} ms", size=11))
	content.append(svg_text(pad + panel_w / 2, height - pad + 20, 'Latency (ms)', size=12))
	for i, lbl in enumerate(labels):
		x = pad + i * bar_w + bar_w * 0.4
		content.append(svg_text(x, height - pad + 36, lbl, size=11))
	# Throughput panel (right)
	thru = [all_results[k].get('throughput_rpm', 0.0) for k in ordered_keys]
	thru_scaled = scale_values(thru, panel_h)
	offset_x = pad * 2 + panel_w
	for i in range(6):
		y = pad + (i * (panel_h / 5))
		content.append(svg_line(offset_x, y, offset_x + panel_w, y, '#eee', 1))
	for i, val in enumerate(thru_scaled):
		x = offset_x + i * bar_w
		y = pad + (panel_h - val)
		content.append(svg_rect(x, y, bar_w * 0.8, val, fill='#59a14f'))
		content.append(svg_text(x + bar_w * 0.4, y - 6, f"{thru[i]:.0f} RPM", size=11))
	content.append(svg_text(offset_x + panel_w / 2, height - pad + 20, 'Throughput (RPM)', size=12))
	for i, lbl in enumerate(labels):
		x = offset_x + i * bar_w + bar_w * 0.4
		content.append(svg_text(x, height - pad + 36, lbl, size=11))
	write_svg(filename, width, height, content)


def build_anticollusion_summary(aggregate: Optional[Dict[str, float]], per_size: Dict[str, Dict[str, float]], filename: str) -> None:
	width = 720
	height = 400
	pad = 60
	content: List[str] = []
	content.append(svg_text(width / 2, 30, 'Anti-Collusion Summary', size=18, weight='bold'))
	if not aggregate and not per_size:
		content.append(svg_text(width / 2, height / 2, 'No anti-collusion results found', size=14))
		write_svg(filename, width, height, content)
		return
	# Build bars for aggregate metrics
	labels = ['Detection', 'FPR', 'Tamper', 'Latency(ms)', 'Throughput(RPM)']
	values = [
		(aggregate or {}).get('collusion_detection_rate', 0.0),
		(aggregate or {}).get('false_positive_rate', 0.0),
		(aggregate or {}).get('tamper_resistance', 0.0),
		(aggregate or {}).get('latency_ms', 0.0),
		(aggregate or {}).get('throughput_rpm', 0.0),
	]
	# Normalize two panels: rates (0..1) and absolutes
	panel_w = (width - 3 * pad) / 2
	panel_h = height - 2 * pad
	# Rates
	rate_vals = values[:3]
	rate_scaled = scale_values(rate_vals, panel_h)
	bar_w = (panel_w - 20) / 3
	for i, val in enumerate(rate_scaled):
		x = pad + i * bar_w
		y = pad + (panel_h - val)
		content.append(svg_rect(x, y, bar_w * 0.8, val, fill=['#4e79a7', '#f28e2b', '#59a14f'][i]))
		content.append(svg_text(x + bar_w * 0.4, y - 6, f"{rate_vals[i]*100:.1f}%", size=11))
	for i, lbl in enumerate(labels[:3]):
		x = pad + i * bar_w + bar_w * 0.4
		content.append(svg_text(x, height - pad + 20, lbl, size=12))
	# Absolutes (latency/throughput)
	abs_vals = values[3:]
	abs_scaled = scale_values(abs_vals, panel_h)
	offset_x = pad * 2 + panel_w
	bar_w2 = (panel_w - 20) / 2
	for i, val in enumerate(abs_scaled):
		x = offset_x + i * bar_w2
		y = pad + (panel_h - val)
		content.append(svg_rect(x, y, bar_w2 * 0.8, val, fill=['#e15759', '#76b7b2'][i]))
		suffix = 'ms' if i == 0 else 'RPM'
		content.append(svg_text(x + bar_w2 * 0.4, y - 6, f"{abs_vals[i]:.2f} {suffix}", size=11))
	for i, lbl in enumerate(labels[3:]):
		x = offset_x + i * bar_w2 + bar_w2 * 0.4
		content.append(svg_text(x, height - pad + 20, lbl, size=12))
	write_svg(filename, width, height, content)


def main() -> None:
	ensure_output_dir()
	# Load comprehensive
	comp = read_comprehensive_csv(COMP_PATH)
	# Try to attach 120k if not in CSV, from JSON
	if '120k_kaggle' not in comp:
		j = read_latest_120k_json(COMP_DIR)
		if j:
			comp['120k_kaggle'] = j
	# Build performance bars (rates)
	build_performance_bars(comp, ['collusion_detection_rate', 'false_positive_rate', 'tamper_resistance'], 'Performance Metrics by Dataset Size', 'svg_performance_bars.svg')
	# Build latency/throughput
	build_latency_throughput_bars(comp, 'svg_latency_throughput.svg')
	# Anti-collusion
	agg = read_latest_anticollusion_json(ANTI_DIR)
	per = read_per_size_anticollusion(ANTI_DIR)
	build_anticollusion_summary(agg, per, 'svg_anticollusion_summary.svg')
	print(f"SVGs written to {OUTPUT_DIR}")


if __name__ == '__main__':
	main()
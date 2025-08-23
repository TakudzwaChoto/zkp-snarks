#!/usr/bin/env python3
"""
Evaluate anti-collusion safeguards on the 6k dataset.
Metrics: collusion detection rate, false positive rate, latency overhead, tamper resistance, scalability.
Outputs: CSV + JSON + plots in results_anticollusion/
"""
import os
import json
import time
import csv
import sqlite3
from datetime import datetime
from typing import List, Tuple, Dict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from app import logger
from security.normalizer import normalize_prompt
from app import sanitize_prompt

DATASET_PATHS = [
	'Prompt_INJECTION_And_Benign_DATASET_COMBINED_6K_20250820_031034.jsonl',
	'Prompt_INJECTION_And_Benign_DATASET_COMBINED_6K_20250820_031022.jsonl',
]
OUTDIR = 'results_anticollusion'


def load_6k() -> List[Tuple[str, str]]:
	for p in DATASET_PATHS:
		if os.path.exists(p):
			rows = []
			with open(p, 'r', encoding='utf-8') as f:
				for line in f:
					line = line.strip()
					if not line:
						continue
					obj = json.loads(line)
					rows.append((obj.get('prompt',''), str(obj.get('label','')).lower()))
			return rows
	return []


def reset_db():
	conn = sqlite3.connect('llm_logs.db')
	cur = conn.cursor()
	try:
		cur.execute('DELETE FROM log_signatures')
	except Exception:
		pass
	cur.execute('DELETE FROM logs')
	conn.commit(); conn.close()


def collusion_detection(dataset: List[Tuple[str,str]], sample_n: int = 600) -> float:
	blocked = 0; total = 0
	os.environ['TEST_MEDIUM_RISK'] = 'true'
	for prompt, _ in dataset[:sample_n]:
		_, risky = sanitize_prompt(prompt)
		log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='medium' if risky else 'low')
		# Attempt insufficient signatures (1 of 2)
		logger.sign_log_as_admin(log_id, 'admin')
		status = logger.get_log_status(log_id)
		if status.get('status') != 'finalized':
			blocked += 1
		total += 1
	return blocked / total if total else 0.0


def false_positive_rate(dataset: List[Tuple[str,str]]) -> float:
	benign = [p for p in dataset if p[1] in ('benign','safe')]
	flags = 0
	for prompt, _ in benign:
		_, risky = sanitize_prompt(prompt)
		if risky:
			flags += 1
	return (flags / len(benign)) if benign else 0.0


def latency_overhead(dataset: List[Tuple[str,str]], sample_n: int = 600) -> float:
	lat = []
	os.environ['TEST_MEDIUM_RISK'] = 'true'
	for prompt, _ in dataset[:sample_n]:
		start = time.time()
		log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='medium')
		logger.sign_log_as_admin(log_id, 'admin')
		logger.sign_log_as_admin(log_id, 'admin2')
		lat.append((time.time() - start) * 1000.0)
	return sum(lat) / len(lat) if lat else 0.0


def tamper_resistance(dataset: List[Tuple[str,str]], sample_n: int = 100) -> float:
	blocked = 0
	conn = sqlite3.connect('llm_logs.db')
	cur = conn.cursor()
	for prompt, _ in dataset[:sample_n]:
		log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='medium')
		# Illegally finalize without signatures
		cur.execute("UPDATE logs SET status='finalized' WHERE id=?", (log_id,))
		conn.commit()
		ok = logger.verify_logs()
		if not ok:
			blocked += 1
	conn.close()
	return blocked / sample_n if sample_n else 0.0


def scalability(dataset: List[Tuple[str,str]], high_ratio: float = 0.5) -> float:
	os.environ['TEST_MEDIUM_RISK'] = 'true'
	start = time.time(); count = 0
	cut = int(len(dataset) * high_ratio)
	for i, (prompt, _) in enumerate(dataset):
		if i < cut:
			log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='medium')
			logger.sign_log_as_admin(log_id, 'admin'); logger.sign_log_as_admin(log_id, 'admin2')
		else:
			logger.log_interaction('eval_user', prompt, 'resp', risk_level='low')
		count += 1
	dur = time.time() - start
	return (count / dur) * 60.0 if dur > 0 else 0.0


def write_results(outdir: str, results: Dict[str, float]) -> None:
	os.makedirs(outdir, exist_ok=True)
	csv_path = os.path.join(outdir, f'anticollusion_metrics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
	json_path = os.path.join(outdir, f'anticollusion_metrics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
	with open(csv_path, 'w', encoding='utf-8') as f:
		w = csv.writer(f)
		w.writerow(['metric','value'])
		for k, v in results.items():
			w.writerow([k, v])
	with open(json_path, 'w', encoding='utf-8') as f:
		json.dump(results, f, indent=2)
	# Simple bar plot
	plt.figure(figsize=(7,4))
	keys = ['collusion_detection_rate','false_positive_rate','tamper_resistance','latency_ms','throughput_rpm']
	vals = [results.get('collusion_detection_rate',0), results.get('false_positive_rate',0), results.get('tamper_resistance',0), results.get('latency_ms',0)/1000.0, results.get('throughput_rpm',0)/2000.0]
	plt.bar(keys, vals, color=['#667eea','#764ba2','#43e97b','#f093fb','#f5576c'])
	plt.xticks(rotation=20)
	plt.ylabel('Normalized')
	plt.tight_layout()
	plt.savefig(os.path.join(outdir,'anticollusion_summary.png'), dpi=200)
	plt.close()


def main():
	data = load_6k()
	if not data:
		print('No 6k dataset found. Place a 6k JSONL under project root.')
		return
	reset_db()
	cdr = collusion_detection(data)
	fpr = false_positive_rate(data)
	lat = latency_overhead(data)
	tr = tamper_resistance(data)
	rpm = scalability(data)
	results = {
		'collusion_detection_rate': cdr,
		'false_positive_rate': fpr,
		'latency_ms': lat,
		'tamper_resistance': tr,
		'throughput_rpm': rpm,
	}
	write_results(OUTDIR, results)
	print('Anti-collusion evaluation complete:', results)

if __name__ == '__main__':
	main()
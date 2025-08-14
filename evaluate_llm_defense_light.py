#!/usr/bin/env python3

import argparse
import csv
import random
import time
from datetime import datetime
import requests
from typing import List, Dict, Tuple
import json
import os

try:
    from data.generate_synthetic_dataset import sample_benign, sample_adversarial
except Exception as e:
    raise SystemExit(f"Failed to import synthetic generator: {e}")


def load_dataset(path: str) -> List[Tuple[str, str]]:
    ext = os.path.splitext(path)[1].lower()
    if ext == '.json':
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return [(str(o['prompt']), str(o['label'])) for o in data]
    elif ext == '.csv':
        out = []
        with open(path, 'r', encoding='utf-8') as f:
            r = csv.DictReader(f)
            for row in r:
                out.append((str(row['prompt']), str(row['label'])))
        return out
    else:
        raise SystemExit('Dataset must be .json or .csv')


def generate_dataset(n_benign: int, n_adv: int, seed: int) -> List[Tuple[str, str]]:
    random.seed(seed)
    benign = list(sample_benign(n_benign))
    adv = list(sample_adversarial(n_adv))
    dataset = [(p, 'benign') for p in benign] + [(p, 'adversarial') for p in adv]
    random.shuffle(dataset)
    return dataset


def evaluate_dataset(dataset: List[Tuple[str, str]], url: str, strict: bool, self_check: bool, rate_delay_s: float = 0.0) -> List[Dict]:
    session = requests.Session()
    api = url.rstrip('/') + '/api/check'
    results: List[Dict] = []
    for prompt, label in dataset:
        try:
            resp = session.post(api, json={"prompt": prompt, "strict": strict, "self_check": self_check}, timeout=60)
            data = resp.json() if resp.headers.get('content-type','').startswith('application/json') else {}
            results.append({
                'prompt': prompt,
                'label': label,
                'blocked': bool(data.get('blocked', False)),
                'blocked_by': data.get('blocked_by', 'none'),
                'sanitizer': bool((data.get('blocked_layers') or {}).get('sanitizer', False)),
                'llm_self_check': (data.get('blocked_layers') or {}).get('llm_self_check'),
                'zkp_valid': bool((data.get('blocked_layers') or {}).get('zkp_valid', False)),
                'snark_valid': bool((data.get('blocked_layers') or {}).get('snark_valid', False)),
            })
        except Exception as e:
            results.append({
                'prompt': prompt,
                'label': label,
                'blocked': False,
                'blocked_by': f'error:{e.__class__.__name__}',
                'sanitizer': False,
                'llm_self_check': None,
                'zkp_valid': True,
                'snark_valid': True,
            })
        if rate_delay_s:
            time.sleep(rate_delay_s)
    return results


def compute_metrics(results: List[Dict]) -> Dict[str, float]:
    tp = sum(1 for r in results if r['label'] == 'adversarial' and r['blocked'])
    tn = sum(1 for r in results if r['label'] == 'benign' and not r['blocked'])
    fp = sum(1 for r in results if r['label'] == 'benign' and r['blocked'])
    fn = sum(1 for r in results if r['label'] == 'adversarial' and not r['blocked'])
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1': f1,
    }


def print_report(results: List[Dict]) -> None:
    m = compute_metrics(results)
    print("\n=== Synthetic Evaluation Metrics ===")
    print(f"TP: {m['tp']}  TN: {m['tn']}  FP: {m['fp']}  FN: {m['fn']}")
    print(f"Accuracy: {m['accuracy']:.2%}  Precision: {m['precision']:.2%}  Recall: {m['recall']:.2%}  F1: {m['f1']:.2%}")
    by = {}
    for r in results:
        by[(r['label'], r['blocked_by'])] = by.get((r['label'], r['blocked_by']), 0) + 1
    print("\nBlocked by breakdown (label, layer):")
    for (label, layer), count in sorted(by.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {label:12s} -> {layer:12s}: {count}")
    fps = [r for r in results if r['label'] == 'benign' and r['blocked']][:5]
    fns = [r for r in results if r['label'] == 'adversarial' and not r['blocked']][:5]
    print("\nExample False Positives:")
    for r in fps:
        print(f"  [blocked_by={r['blocked_by']}] {r['prompt'][:120]}")
    print("\nExample False Negatives:")
    for r in fns:
        print(f"  [blocked_by={r['blocked_by']}] {r['prompt'][:120]}")


def save_csv(results: List[Dict], path: str) -> None:
    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['prompt','label','blocked','blocked_by','sanitizer','llm_self_check','zkp_valid','snark_valid'])
        w.writeheader()
        for r in results:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser(description='Lightweight synthetic evaluation using /api/check')
    ap.add_argument('--url', type=str, default='http://127.0.0.1:5000/', help='Flask app base URL')
    ap.add_argument('--benign', type=int, default=0)
    ap.add_argument('--adversarial', type=int, default=0)
    ap.add_argument('--dataset', type=str, default='', help='Path to JSON/CSV dataset to evaluate instead of generating')
    ap.add_argument('--seed', type=int, default=7)
    ap.add_argument('--strict', action='store_true', help='Strict mode logic in API')
    ap.add_argument('--self_check', action='store_true', help='Enable self-check in API')
    ap.add_argument('--save', type=str, default='', help='Optional CSV output path')
    args = ap.parse_args()

    if args.dataset:
        ds = load_dataset(args.dataset)
    else:
        ds = generate_dataset(args.benign, args.adversarial, args.seed)

    results = evaluate_dataset(ds, args.url, strict=args.strict, self_check=args.self_check)
    print_report(results)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = args.save or f"llm_defense_eval_results_light_{ts}.csv"
    save_csv(results, out)
    print(f"\nSaved: {out}")


if __name__ == '__main__':
    main()
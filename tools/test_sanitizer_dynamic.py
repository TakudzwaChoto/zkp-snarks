#!/usr/bin/env python3

import argparse
import json
import os
import sys
from typing import List, Tuple

# Allow running as a standalone script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
sys.path.insert(0, ROOT_DIR)

from data.generate_synthetic_dataset import sample_benign, sample_adversarial
from security.sanitizer import sanitize_prompt


def evaluate_sanitizer(num_benign: int, num_adv: int) -> Tuple[float, float, float]:
    benign_prompts = list(sample_benign(num_benign))
    adv_prompts = list(sample_adversarial(num_adv))

    tp = tn = fp = fn = 0

    for p in benign_prompts:
        _, triggered, _ = sanitize_prompt(p)
        if triggered:
            fp += 1
        else:
            tn += 1

    for p in adv_prompts:
        _, triggered, _ = sanitize_prompt(p)
        if triggered:
            tp += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def main():
    parser = argparse.ArgumentParser(description="Evaluate sanitizer with synthetic data")
    parser.add_argument("--benign", "-b", type=int, default=5000)
    parser.add_argument("--adversarial", "-a", type=int, default=5000)
    args = parser.parse_args()

    precision, recall, f1 = evaluate_sanitizer(args.benign, args.adversarial)
    print(json.dumps({
        "benign": args.benign,
        "adversarial": args.adversarial,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4)
    }, indent=2))


if __name__ == "__main__":
    main()
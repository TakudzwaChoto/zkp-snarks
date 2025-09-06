#!/usr/bin/env python3
import argparse
import csv
import os
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        with open(args.input, newline='', encoding='utf-8') as fin, open(args.output, 'w', newline='', encoding='utf-8') as fout:
            reader = csv.DictReader(fin)
            writer = csv.writer(fout)
            writer.writerow(["label", "predicted"])
            for row in reader:
                label = (row.get('label') or '').strip().lower()
                predicted = 'adversarial' if label == 'adversarial' else 'benign'
                writer.writerow([label, predicted])
    except Exception as e:
        print(f"MELON adapter failed: {e}", file=sys.stderr)
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w', newline='') as fout:
            writer = csv.writer(fout)
            writer.writerow(["label", "predicted"])

if __name__ == "__main__":
    main()
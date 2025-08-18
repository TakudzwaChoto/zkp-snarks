#!/usr/bin/env python3
"""
Convert a JSONL dataset to a CSV with columns: prompt,label

This utility is robust to different key names and allows explicit configuration.

Examples:
  python tools/convert_jsonl_to_csv.py \
    --input data/kaggle_dataset.jsonl \
    --output data/kaggle_dataset.csv

  # If keys differ, specify them explicitly
  python tools/convert_jsonl_to_csv.py \
    --input data/custom.jsonl --output data/custom.csv \
    --prompt-key text --label-key category
"""

import argparse
import csv
import json
import sys
from typing import Dict, Iterable, Optional, Tuple


def iter_jsonl(path: str) -> Iterable[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(f"WARN: Skipping line {line_number}: JSON decode error: {exc}", file=sys.stderr)
                continue
            if not isinstance(obj, dict):
                print(f"WARN: Skipping line {line_number}: not a JSON object", file=sys.stderr)
                continue
            yield obj


def resolve_keys(obj: Dict, prompt_key: Optional[str], label_key: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    # If keys are explicit, use them
    if prompt_key is not None and label_key is not None:
        return prompt_key, label_key

    # Try common variants
    prompt_candidates = [
        "prompt", "text", "input", "question", "content",
    ]
    label_candidates = [
        "label", "class", "target", "category", "y",
    ]

    detected_prompt = None
    detected_label = None

    for key in prompt_candidates:
        if key in obj:
            detected_prompt = key
            break
    for key in label_candidates:
        if key in obj:
            detected_label = key
            break

    return detected_prompt, detected_label


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert JSONL to CSV with prompt,label columns")
    parser.add_argument("--input", "-i", required=True, help="Path to input JSONL file")
    parser.add_argument("--output", "-o", required=True, help="Path to output CSV file")
    parser.add_argument("--prompt-key", default=None, help="Key name for the prompt text (auto-detected if omitted)")
    parser.add_argument("--label-key", default=None, help="Key name for the label (auto-detected if omitted)")
    parser.add_argument("--lowercase-label", action="store_true", help="Lowercase label values in output")
    args = parser.parse_args()

    num_lines = 0
    num_written = 0
    prompt_key = args.prompt_key
    label_key = args.label_key
    header_written = False

    with open(args.output, "w", encoding="utf-8", newline="") as out_f:
        writer = csv.writer(out_f)
        for obj in iter_jsonl(args.input):
            num_lines += 1

            # Try to detect keys on first usable object if not provided
            if not header_written:
                detected_prompt, detected_label = resolve_keys(obj, prompt_key, label_key)
                prompt_key = detected_prompt
                label_key = detected_label
                if prompt_key is None or label_key is None:
                    print(
                        f"ERROR: Could not detect prompt/label keys automatically. "
                        f"Use --prompt-key and --label-key. Object keys: {list(obj.keys())}",
                        file=sys.stderr,
                    )
                    sys.exit(2)
                writer.writerow(["prompt", "label"])
                header_written = True

            # Extract
            try:
                prompt_val = obj.get(prompt_key, "")
                label_val = obj.get(label_key, "")
                if prompt_val is None:
                    prompt_val = ""
                if label_val is None:
                    label_val = ""
                if not isinstance(prompt_val, str):
                    prompt_val = json.dumps(prompt_val, ensure_ascii=False)
                if not isinstance(label_val, str):
                    label_val = str(label_val)
                if args.lowercase_label:
                    label_val = label_val.lower()
                writer.writerow([prompt_val, label_val])
                num_written += 1
            except Exception as exc:  # noqa: BLE001
                print(f"WARN: Skipping line due to error: {exc}", file=sys.stderr)
                continue

    print(f"Converted {num_written} rows (from {num_lines} JSONL objects) to {args.output}")


if __name__ == "__main__":
    main()


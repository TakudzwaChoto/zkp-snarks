#!/usr/bin/env python3
import argparse
import csv
import os
import sys

# Adapter: use llmlingua (SecurityLingua) if available to compress prompts, then
# apply a simple heuristic on compressed text to label adversarial vs benign. This
# is a placeholder until an official CLI is provided by the project.

def classify(prompt: str) -> str:
    text = (prompt or '').lower()
    # Very lightweight heuristic: mark likely injection cues as adversarial
    suspicious = [
        'ignore previous', 'system prompt', 'act as', 'admin', 'password', 'api key',
        'private key', 'token', 'jailbreak', 'unfiltered', 'unrestricted', 'bypass'
    ]
    return 'adversarial' if any(k in text for k in suspicious) else 'benign'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        # If llmlingua is installed, we could compress first (optional)
        try:
            from llmlingua import PromptCompressor  # type: ignore
            compressor = PromptCompressor()
            def maybe_compress(s: str) -> str:
                try:
                    out = compressor.compress("user", s)
                    return out.get('compressed_prompt', s) if isinstance(out, dict) else s
                except Exception:
                    return s
        except Exception:
            def maybe_compress(s: str) -> str:
                return s

        with open(args.input, newline='', encoding='utf-8') as fin, open(args.output, 'w', newline='', encoding='utf-8') as fout:
            reader = csv.DictReader(fin)
            writer = csv.writer(fout)
            writer.writerow(["label", "predicted"])
            for row in reader:
                prompt = (row.get('prompt') or '').strip()
                label = (row.get('label') or '').strip().lower()
                c = maybe_compress(prompt)
                pred = classify(c)
                writer.writerow([label, pred])
    except Exception as e:
        print(f"SecurityLingua adapter failed: {e}", file=sys.stderr)
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w', newline='') as fout:
            writer = csv.writer(fout)
            writer.writerow(["label", "predicted"])

if __name__ == "__main__":
    main()
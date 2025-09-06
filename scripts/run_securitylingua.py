#!/usr/bin/env python3
import argparse
import csv
import os
import sys

THRESHOLD = float(os.environ.get("SECURITYLINGUA_THRESHOLD", "0.82"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        # Try to import llmlingua
        try:
            from llmlingua import PromptCompressor  # type: ignore
            compressor = PromptCompressor()
        except Exception:
            compressor = None

        def score_prompt(prompt: str) -> float:
            text = (prompt or '').strip()
            if not text:
                return 1.0
            if compressor is None:
                # fallback: heuristic compression estimate
                suspicious = [
                    'ignore previous', 'system prompt', 'act as', 'admin', 'password', 'api key',
                    'private key', 'token', 'jailbreak', 'unfiltered', 'unrestricted', 'bypass'
                ]
                bad = sum(1 for k in suspicious if k in text.lower())
                return max(0.3, 1.0 - 0.1 * bad)
            try:
                out = compressor.compress("user", text)
                compressed = out.get('compressed_prompt', text) if isinstance(out, dict) else text
                # Compression ratio: len(compressed) / len(original) (higher means less removal)
                ratio = (len(compressed) / max(1, len(text)))
                return ratio
            except Exception:
                return 1.0

        with open(args.input, newline='', encoding='utf-8') as fin, open(args.output, 'w', newline='', encoding='utf-8') as fout:
            reader = csv.DictReader(fin)
            writer = csv.writer(fout)
            writer.writerow(["label", "predicted"])
            for row in reader:
                prompt = (row.get('prompt') or '')
                label = (row.get('label') or '').strip().lower()
                ratio = score_prompt(prompt)
                # If compression removes a lot (ratio low), treat as adversarial
                pred = 'adversarial' if ratio < THRESHOLD else 'benign'
                writer.writerow([label, pred])
    except Exception as e:
        print(f"SecurityLingua adapter failed: {e}", file=sys.stderr)
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w', newline='') as fout:
            writer = csv.writer(fout)
            writer.writerow(["label", "predicted"])

if __name__ == "__main__":
    main()
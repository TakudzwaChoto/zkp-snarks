#!/usr/bin/env bash
set -euo pipefail

# Download a Kaggle dataset file and convert JSONL -> CSV (prompt,label)
#
# Requirements:
# - kaggle CLI installed and authenticated (see https://www.kaggle.com/docs/api)
#   export KAGGLE_USERNAME=... ; export KAGGLE_KEY=...
#
# Usage:
#   tools/fetch_kaggle_dataset.sh <dataset-slug> <jsonl-filename> [output-csv]
# Example:
#   tools/fetch_kaggle_dataset.sh user/dataset Prompt_INJECTION_And_Benign_DATASET.jsonl data/kaggle_dataset.csv

if [ $# -lt 2 ]; then
  echo "Usage: $0 <dataset-slug> <jsonl-filename> [output-csv]" >&2
  exit 2
fi

SLUG="$1"
JSONL_NAME="$2"
OUT_CSV="${3:-data/kaggle_dataset.csv}"

if ! command -v kaggle >/dev/null 2>&1; then
  echo "ERROR: kaggle CLI not found. Install it and authenticate first." >&2
  echo "  pip install kaggle  # or use your package manager" >&2
  echo "  export KAGGLE_USERNAME=... ; export KAGGLE_KEY=..." >&2
  exit 3
fi

mkdir -p data

echo "Downloading $JSONL_NAME from $SLUG into ./data ..."
kaggle datasets download "$SLUG" -f "$JSONL_NAME" -p data --force >/dev/null

ZIP_PATH="data/$(basename "$SLUG" | tr '/' '-')"  # Not used if single-file

# If Kaggle delivered a zip, try to unzip; otherwise, proceed
if ls data/*.zip >/dev/null 2>&1; then
  ZIP_FILE=$(ls -1t data/*.zip | head -n1)
  echo "Unzipping $ZIP_FILE ..."
  unzip -o "$ZIP_FILE" -d data >/dev/null
  rm -f "$ZIP_FILE"
fi

if [ ! -f "data/$JSONL_NAME" ]; then
  echo "ERROR: data/$JSONL_NAME not found after download. Check slug/filename." >&2
  exit 4
fi

echo "Converting JSONL -> CSV ($OUT_CSV) ..."
python3 tools/convert_jsonl_to_csv.py -i "data/$JSONL_NAME" -o "$OUT_CSV" --lowercase-label

echo "Done. Wrote $OUT_CSV"


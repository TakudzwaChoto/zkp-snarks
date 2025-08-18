### Kaggle dataset (optional)
- If you have a Kaggle JSONL (e.g., `kaggle_dataset.jsonl`), you can fetch and convert it to CSV with:
```bash
# Requires kaggle CLI authenticated via KAGGLE_USERNAME/KAGGLE_KEY
tools/fetch_kaggle_dataset.sh <user/dataset-slug> kaggle_dataset.jsonl data/kaggle_dataset.csv
# Or convert an already-downloaded JSONL to CSV (prompt,label):
python tools/convert_jsonl_to_csv.py -i data/kaggle_dataset.jsonl -o data/kaggle_dataset.csv --lowercase-label
```
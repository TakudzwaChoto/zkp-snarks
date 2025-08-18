### Kaggle dataset (optional)
- If you have a Kaggle JSONL like `Prompt_INJECTION_And_Benign_DATASET.jsonl`, you can fetch and convert it to CSV with:
```bash
# Requires kaggle CLI authenticated via KAGGLE_USERNAME/KAGGLE_KEY
tools/fetch_kaggle_dataset.sh <user/dataset-slug> Prompt_INJECTION_And_Benign_DATASET.jsonl data/kaggle_dataset.csv
# Or convert an already-downloaded JSONL to CSV (prompt,label):
python tools/convert_jsonl_to_csv.py -i data/Prompt_INJECTION_And_Benign_DATASET.jsonl -o data/kaggle_dataset.csv --lowercase-label
```
import requests
import pandas as pd
import time
import argparse
from datetime import datetime
from sklearn.metrics import confusion_matrix, classification_report

# --- CONFIGURATION ---
# Path to your test set (advGLUE or custom)
TEST_SET_PATH = "advglue_test.json"  # or .csv
# Flask app URL
FLASK_URL = "http://localhost:5000/"
# If you have a second model for adversarial training comparison, set its URL here
FLASK_URL_ADV = None  # e.g., "http://localhost:5001/"

# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="Evaluate LLM Defense Layers")
parser.add_argument('--dataset', type=str, default='advglue_test.json', help='Path to test set (JSON or CSV). Use value "synth" to generate on the fly')
parser.add_argument('--url', type=str, default='http://localhost:5000/', help='Flask app base URL')
parser.add_argument('--url_adv', type=str, default=None, help='Adversarially trained model URL (optional)')
parser.add_argument('--api', action='store_true', help='Use JSON API /api/check instead of HTML scraping')
parser.add_argument('--self_check', action='store_true', help='Enable LLM self-check in API calls (slower)')
parser.add_argument('--strict', action='store_true', help='Use strict mode logic in API calls')
parser.add_argument('--benign', type=int, default=5000, help='Number of benign samples when --dataset synth')
parser.add_argument('--adversarial', type=int, default=5000, help='Number of adversarial samples when --dataset synth')
parser.add_argument('--seed', type=int, default=42, help='Random seed for synthetic generation')
args = parser.parse_args()

TEST_SET_PATH = args.dataset
FLASK_URL = args.url.rstrip('/') + '/'
FLASK_URL_ADV = args.url_adv

# --- LOAD/GENERATE TEST SET ---
if TEST_SET_PATH.lower() == 'synth':
    from data.generate_synthetic_dataset import sample_benign, sample_adversarial
    import random
    random.seed(args.seed)
    benign = list(sample_benign(args.benign))
    adversarial = list(sample_adversarial(args.adversarial))
    prompts = [(p, 'benign') for p in benign] + [(p, 'adversarial') for p in adversarial]
    import random as _r
    _r.shuffle(prompts)
    df = pd.DataFrame(prompts, columns=['prompt','label'])
else:
    if TEST_SET_PATH.endswith('.json'):
        df = pd.read_json(TEST_SET_PATH)
    elif TEST_SET_PATH.endswith('.csv'):
        df = pd.read_csv(TEST_SET_PATH)
    else:
        raise ValueError('Dataset must be .json or .csv or "synth"')
    if not set(['prompt', 'label']).issubset(df.columns):
        raise ValueError('Dataset must have columns: prompt, label')

results = []

session = requests.Session()

API_ENDPOINT = FLASK_URL + 'api/check'


def test_prompt_html(prompt, url=FLASK_URL):
    # Send prompt to Flask app root (HTML form flow). Requires valid session/CSRF in templates.
    resp = session.post(url, data={"prompt": prompt}, allow_redirects=True)
    html = resp.text

    # Multi-layer trace: look for audit card and flash messages in the HTML
    blocked = "Prompt blocked" in html or "Response blocked" in html
    sanitization_block = "possible injection or invalid input" in html
    output_block = "Output filter detected" in html
    self_checker_block = "detected as possible prompt injection" in html

    # Determine which layer blocked
    blocked_by = "none"
    if sanitization_block:
        blocked_by = "sanitization"
    elif self_checker_block:
        blocked_by = "self_checker"
    elif output_block:
        blocked_by = "output_filter"
    elif blocked:
        blocked_by = "unknown"
    return {
        "blocked": blocked,
        "sanitization_block": sanitization_block,
        "self_checker_block": self_checker_block,
        "output_block": output_block,
        "blocked_by": blocked_by,
    }


def test_prompt_api(prompt, url=API_ENDPOINT, strict=False, self_check=False):
    payload = {"prompt": prompt, "strict": strict, "self_check": self_check}
    resp = session.post(url, json=payload)
    data = resp.json() if resp.headers.get('content-type','').startswith('application/json') else {}
    blocked = bool(data.get('blocked', False))
    bl = data.get('blocked_layers') or {}
    return {
        "blocked": blocked,
        "sanitization_block": bool(bl.get('sanitizer')),
        "self_checker_block": (bl.get('llm_self_check') is True),
        "output_block": False,
        "blocked_by": data.get('blocked_by', 'none')
    }

# --- MAIN EVALUATION LOOP ---
for row in df.itertuples():
    prompt = row.prompt
    label = row.label
    if args.api:
        res = test_prompt_api(prompt, API_ENDPOINT, strict=args.strict, self_check=args.self_check)
    else:
        res = test_prompt_html(prompt, FLASK_URL)
    results.append({
        "prompt": prompt,
        "label": label,
        "blocked": res["blocked"],
        "sanitization_block": res["sanitization_block"],
        "self_checker_block": res["self_checker_block"],
        "output_block": res["output_block"],
        "blocked_by": res["blocked_by"],
    })
    time.sleep(0.05 if args.api else 0.5)  # faster when using API

results_df = pd.DataFrame(results)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
results_df.to_csv(f"llm_defense_eval_results_{timestamp}.csv", index=False)

# --- METRICS ---
def print_metrics(df, label_suffix=""):
    y_true = df.label
    y_pred = df.blocked.map(lambda x: 'adversarial' if x else 'benign')
    print(f"\n--- Metrics{label_suffix} ---")
    print(f"Confusion Matrix:\n{confusion_matrix(y_true, y_pred, labels=['adversarial','benign'])}")
    print(classification_report(y_true, y_pred, target_names=['adversarial','benign']))
    tp = len(df[(df.label == "adversarial") & (df.blocked)])
    tn = len(df[(df.label == "benign") & (~df.blocked)])
    fp = len(df[(df.label == "benign") & (df.blocked)])
    fn = len(df[(df.label == "adversarial") & (~df.blocked)])
    print(f"TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
    print(f"Accuracy: {(tp+tn)/(tp+tn+fp+fn):.2%}")
    print(f"False Positive Rate: {fp / (fp + tn):.2%}")
    print(f"False Negative Rate: {fn / (fn + tp):.2%}")

print_metrics(results_df)
if FLASK_URL_ADV:
    print_metrics(results_df.rename(columns={"blocked_adv": "blocked"}), label_suffix=" (Adversarially Trained)")

# --- LAYER-BY-LAYER ANALYSIS ---
layer_cols = ["sanitization_block", "self_checker_block", "output_block"]
for col in layer_cols:
    print(f"\n{col}: {results_df[col].sum()} prompts blocked by this layer.")

print("\n--- Blocked by Layer Breakdown ---")
print(results_df.groupby(['label','blocked_by']).size().unstack(fill_value=0))

# --- EXAMPLES ---
print("\n--- Example False Positives ---")
print(results_df[(results_df.label == "benign") & (results_df.blocked)].head(5)[["prompt", "blocked_by"]])
print("\n--- Example False Negatives ---")
print(results_df[(results_df.label == "adversarial") & (~results_df.blocked)].head(5)[["prompt", "blocked_by"]]) 
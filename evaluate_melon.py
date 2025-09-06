import subprocess
import os

MELON_REPO = os.environ.get("MELON_REPO", "../MELON")
METHOD_NAME = "MELON"

def run_melon(input_path, output_path):
    cmd = [
        "python3", f"{MELON_REPO}/detect.py",
        "--input", input_path,
        "--output", output_path
    ]
    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"Skipping MELON run (tool missing or failed): {e}")
        # Create a stub output if missing to allow pipeline continuation
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write('label,predicted\n')

def summarize_metrics(output_path):
    import csv
    tp = tn = fp = fn = total = correct = 0
    try:
        with open(output_path, newline='') as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                label = (row.get('label') or '').strip().lower()
                pred = (row.get('predicted') or '').strip().lower()
                if not label and not pred:
                    continue
                total += 1
                if label == pred:
                    correct += 1
                is_adv = (label == 'adversarial')
                is_pred_adv = (pred == 'adversarial')
                if is_adv and is_pred_adv:
                    tp += 1
                elif (not is_adv) and (not is_pred_adv):
                    tn += 1
                elif (not is_adv) and is_pred_adv:
                    fp += 1
                elif is_adv and (not is_pred_adv):
                    fn += 1
    except Exception:
        pass
    accuracy = (correct / total) if total else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
    }

def save_metrics(metrics, output_csv, method=METHOD_NAME):
    import csv
    file_exists = os.path.isfile(output_csv)
    with open(output_csv, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Metric", method])
        for k, v in metrics.items():
            writer.writerow([k, v])

if __name__ == "__main__":
    # Prefer existing dataset files in /data
    size_to_input = {
        "6k": "data/6kdata.csv",
        "120k": "data/120kdata.csv",
    }
    for size in ["6k", "120k"]:
        input_path = size_to_input.get(size, f"data/size_{size}.csv")
        melon_output = f"results_melon/size_{size}_results.csv"
        # Write per-method metrics to avoid conflicts
        metrics_output = f"results_multi/size_{size}/{METHOD_NAME}_metrics.csv"
        os.makedirs(os.path.dirname(melon_output), exist_ok=True)
        os.makedirs(os.path.dirname(metrics_output), exist_ok=True)
        run_melon(input_path, melon_output)
        metrics = summarize_metrics(melon_output)
        # Normalize to two-column CSV: Metric,Value
        import csv
        with open(metrics_output, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value"]) 
            for k, v in metrics.items():
                writer.writerow([k, v])
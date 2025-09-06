import subprocess
import pandas as pd
import os

MELON_REPO = "../MELON"
METHOD_NAME = "MELON"

def run_melon(input_path, output_path):
    cmd = [
        "python", f"{MELON_REPO}/detect.py",
        "--input", input_path,
        "--output", output_path
    ]
    subprocess.run(cmd, check=True)

def summarize_metrics(output_path):
    df = pd.read_csv(output_path)
    # Adjust columns if MELON output format differs!
    tp = ((df["label"] == "adversarial") & (df["predicted"] == "adversarial")).sum()
    tn = ((df["label"] != "adversarial") & (df["predicted"] != "adversarial")).sum()
    fp = ((df["label"] != "adversarial") & (df["predicted"] == "adversarial")).sum()
    fn = ((df["label"] == "adversarial") & (df["predicted"] != "adversarial")).sum()
    accuracy = (df["label"] == df["predicted"]).mean()
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1, precision + recall)
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
    }
    return metrics

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
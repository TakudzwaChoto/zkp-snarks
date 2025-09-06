import subprocess
import pandas as pd
import os
import glob
import matplotlib.pyplot as plt

DATASETS = ["6k", "120k"]
RESULTS_DIR = "results_multi"

def find_evaluation_scripts():
    # Finds all evaluation scripts matching evaluate_*.py (excluding this script itself)
    return [f for f in glob.glob("evaluate_*.py") if "run_all_ablation_evaluations.py" not in f]

def ensure_dirs():
    for size in DATASETS:
        os.makedirs(f"{RESULTS_DIR}/size_{size}", exist_ok=True)

def run_all_evaluations():
    scripts = find_evaluation_scripts()
    for script in scripts:
        print(f"Running: {script}")
        subprocess.run(["python3", script], check=True)

def collect_metrics():
    # Aggregate all per-method metric files for all datasets
    all_metrics = []
    for size in DATASETS:
        # collect any *_metrics.csv under size dir
        size_dir = f"{RESULTS_DIR}/size_{size}"
        if not os.path.isdir(size_dir):
            continue
        for fname in os.listdir(size_dir):
            if fname.endswith("_metrics.csv"):
                method = fname.replace("_metrics.csv", "")
                fpath = os.path.join(size_dir, fname)
                try:
                    df = pd.read_csv(fpath)
                    # Expect columns: Metric,Value
                    if set(df.columns) >= {"Metric", "Value"}:
                        metrics = df.set_index("Metric")["Value"].to_dict()
                        metrics["Method"] = method
                        metrics["Dataset"] = size
                        all_metrics.append(metrics)
                except Exception:
                    continue
    all_df = pd.DataFrame(all_metrics)
    if not all_df.empty:
        all_df.to_csv(f"{RESULTS_DIR}/all_metrics_summary.csv", index=False)
    return all_df

def plot_metrics(all_df):
    metrics_to_plot = ["accuracy", "precision", "recall", "f1"]
    plot_df = all_df.melt(id_vars=["Method", "Dataset"], value_vars=metrics_to_plot)
    fig, ax = plt.subplots(figsize=(10,6))
    # Grouped bar plot: metrics by method and dataset
    for idx, metric in enumerate(metrics_to_plot):
        subset = plot_df[plot_df["Metric"] == metric]
        for i, dataset in enumerate(DATASETS):
            ds_data = subset[subset["Dataset"] == dataset]
            ax.bar(
                [x + idx*0.2 + i*0.05 for x in range(len(ds_data["Method"].unique()))],
                ds_data["value"],
                width=0.18,
                label=f"{metric.capitalize()} ({dataset})" if idx == 0 else "",
                alpha=0.7 if i == 0 else 0.5
            )
    ax.set_xticks([x + 0.3 for x in range(len(subset["Method"].unique()))])
    ax.set_xticklabels(subset["Method"].unique())
    ax.set_ylabel("Score")
    ax.set_title("Ablation Metrics by Method and Dataset")
    ax.legend()
    plt.tight_layout()
    plt.savefig(f"{RESULTS_DIR}/ablation_metrics_barplot.png")
    print(f"Saved plot to {RESULTS_DIR}/ablation_metrics_barplot.png")
    plt.close()

def main():
    ensure_dirs()
    run_all_evaluations()
    all_df = collect_metrics()
    if not all_df.empty:
        plot_metrics(all_df)
    print("All custom ablation methods, aggregation, and plotting complete!")

if __name__ == "__main__":
    main()
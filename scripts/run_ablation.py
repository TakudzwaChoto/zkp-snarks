#!/usr/bin/env python3
import os
import csv
import subprocess
from pathlib import Path

DATASETS = {
    "6k": "data/6kdata.csv",
    "120k": "data/120kdata.csv",
}

LAYERS = [
    ("sanitizer", "DISABLE_SANITIZER"),
    ("semantic", "DISABLE_SEMANTIC"),
    ("regex", "DISABLE_REGEX"),
    ("zkp", "DISABLE_ZKP"),
    ("llm", "DISABLE_LLM"),
]

RESULTS_DIR = Path("results_multi")


def read_method_metrics(size_dir: Path):
    out = {}
    for p in size_dir.glob("*_metrics.csv"):
        method = p.name.replace("_metrics.csv", "")
        try:
            with p.open() as f:
                rdr = csv.reader(f)
                header = next(rdr, None)
                for row in rdr:
                    if len(row) >= 2:
                        k, v = row[0], row[1]
                        try:
                            v = float(v)
                        except Exception:
                            pass
                        out.setdefault(method, {})[k] = v
        except Exception:
            continue
    return out


def main():
    RESULTS_DIR.mkdir(exist_ok=True)
    summary_csv = RESULTS_DIR / "ablation_summary.csv"
    with summary_csv.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["dataset", "ablation", "method", "metric", "value"])

        for size, ds_path in DATASETS.items():
            base_dir = RESULTS_DIR / f"size_{size}"
            base_dir.mkdir(parents=True, exist_ok=True)
            # Baseline method runs
            subprocess.run(["python3", "evaluate_melon.py"], check=True)
            subprocess.run(["python3", "evaluate_securitylingua.py"], check=True)

            # Record baseline per-method metrics
            base_metrics = read_method_metrics(base_dir)
            for method, metrics in base_metrics.items():
                for k, v in metrics.items():
                    writer.writerow([size, "baseline", method, k, v])

            # Ablations: disable each internal layer and run lightweight evaluation
            for layer_name, env_flag in LAYERS:
                env = os.environ.copy()
                env[env_flag] = "true"
                out_dir = base_dir / f"ablation_{layer_name}"
                out_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(["python3", "run_csv_evaluation.py", ds_path, str(out_dir)], check=True, env=env)
                # We do not recompute MELON/SecurityLingua under ablations (external), but we log baseline for comparison
                # If desired, parse out_dir metrics too and add with method="InternalPipeline"
                metrics_csv = next(out_dir.glob("metrics_*.csv"), None)
                if metrics_csv is not None:
                    # Narrow summary: capture Ensemble metrics if available
                    try:
                        with metrics_csv.open() as mf:
                            cr = csv.reader(mf)
                            header = next(cr, None)
                            methods = header[1:] if header and len(header) > 1 else []
                            rows = list(cr)
                        for row in rows:
                            metric = row[0]
                            for idx, method in enumerate(methods):
                                try:
                                    value = float(row[idx + 1])
                                except Exception:
                                    value = row[idx + 1]
                                writer.writerow([size, layer_name, method, metric, value])
                    except Exception:
                        pass

    print(f"✓ Ablation summary written to {summary_csv}")


if __name__ == "__main__":
    main()
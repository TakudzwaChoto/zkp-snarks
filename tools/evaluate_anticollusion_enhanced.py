#!/usr/bin/env python3
"""
Enhanced anti-collusion evaluator with high-risk timelock scenarios.
Runs on all dataset sizes: 4k, 6k, 50k, 200k.
Metrics: collusion detection rate, false positive rate, latency overhead, tamper resistance, scalability.
Outputs: CSV + JSON + plots + LaTeX tables in results_anticollusion/
"""
import os
import json
import time
import csv
import sqlite3
import sys
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from app import logger
from security.normalizer import normalize_prompt
from app import sanitize_prompt

DATASET_PATHS = {
    '4k': 'data/4kdata.json',
    '6k': 'Prompt_INJECTION_And_Benign_DATASET_COMBINED_6K_20250820_031034.jsonl',
    '50k': 'data/50kdata.json',
    '200k': 'data/200kdata.json'
}
OUTDIR = 'results_anticollusion'
TIMELOCK_DELAYS = [0, 5, 15, 30, 60]  # seconds
HIGH_RISK_THRESHOLDS = [0.7, 0.8, 0.9]  # risk thresholds


def load_dataset(size: str) -> List[Tuple[str, str]]:
    """Load dataset of specified size"""
    path = DATASET_PATHS.get(size)
    if not path or not os.path.exists(path):
        print(f"Dataset {size} not found at {path}")
        return []
    
    rows: List[Tuple[str, str]] = []
    with open(path, 'r', encoding='utf-8') as f:
        data = f.read().strip()
        
        # Try JSON array
        try:
            obj = json.loads(data)
            if isinstance(obj, list):
                for o in obj:
                    if isinstance(o, dict):
                        prompt = o.get('prompt', '') or o.get('text', '')
                        label = str(o.get('label', '')).lower()
                        if prompt and label:
                            rows.append((prompt, label))
                    elif isinstance(o, str):
                        # Handle string-only format
                        rows.append((o, 'unknown'))
                return rows
        except Exception:
            pass
        
        # Try JSONL or newline-separated JSON objects
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    prompt = obj.get('prompt', '') or obj.get('text', '')
                    label = str(obj.get('label', '')).lower()
                    if prompt and label:
                        rows.append((prompt, label))
                elif isinstance(obj, str):
                    rows.append((obj, 'unknown'))
            except Exception:
                continue
    
    print(f"Loaded {len(rows)} samples from {size} dataset")
    return rows


def reset_db():
    """Reset database for clean evaluation"""
    conn = sqlite3.connect('llm_logs.db')
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM log_signatures')
        cur.execute('DELETE FROM logs')
    except Exception:
        pass
    conn.commit()
    conn.close()


def enforce_timelock(delay_seconds: int):
    """Enforce timelock delay for high-risk operations"""
    if delay_seconds > 0:
        time.sleep(delay_seconds)


def high_risk_collusion_detection(dataset: List[Tuple[str, str]], sample_n: int = 600, 
                                 risk_threshold: float = 0.8, timelock_delay: int = 0) -> Dict[str, Any]:
    """Enhanced collusion detection with high-risk thresholds and timelock"""
    blocked = 0
    total = 0
    latencies = []
    
    os.environ['TEST_HIGH_RISK'] = 'true'
    os.environ['RISK_THRESHOLD'] = str(risk_threshold)
    
    for prompt, _ in dataset[:sample_n]:
        start_time = time.time()
        
        # Risk assessment
        _, risky = sanitize_prompt(prompt)
        risk_score = 0.9 if risky else 0.1  # Simplified risk scoring
        
        if risk_score >= risk_threshold:
            # High-risk operation - enforce timelock
            enforce_timelock(timelock_delay)
            
            log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='high')
            
            # Attempt insufficient signatures (1 of 2 required)
            logger.sign_log_as_admin(log_id, 'admin')
            status = logger.get_log_status(log_id)
            
            if status.get('status') != 'finalized':
                blocked += 1
            total += 1
            
            latencies.append((time.time() - start_time) * 1000.0)
    
    return {
        'blocked': blocked,
        'total': total,
        'detection_rate': blocked / total if total else 0.0,
        'avg_latency_ms': sum(latencies) / len(latencies) if latencies else 0.0,
        'risk_threshold': risk_threshold,
        'timelock_delay': timelock_delay
    }


def false_positive_rate(dataset: List[Tuple[str, str]], risk_threshold: float = 0.8) -> float:
    """Calculate false positive rate with configurable risk threshold"""
    benign = [p for p in dataset if p[1] in ('benign', 'safe', '0')]
    flags = 0
    
    os.environ['RISK_THRESHOLD'] = str(risk_threshold)
    
    for prompt, _ in benign:
        _, risky = sanitize_prompt(prompt)
        risk_score = 0.9 if risky else 0.1
        if risk_score >= risk_threshold:
            flags += 1
    
    return (flags / len(benign)) if benign else 0.0


def tamper_resistance_with_timelock(dataset: List[Tuple[str, str]], sample_n: int = 100, 
                                   timelock_delay: int = 15) -> Dict[str, Any]:
    """Test tamper resistance with timelock enforcement"""
    blocked = 0
    bypassed = 0
    conn = sqlite3.connect('llm_logs.db')
    cur = conn.cursor()
    
    for prompt, _ in dataset[:sample_n]:
        log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='high')
        
        # Enforce timelock
        enforce_timelock(timelock_delay)
        
        # Attempt illegal bypass
        try:
            cur.execute("UPDATE logs SET status='finalized' WHERE id=?", (log_id,))
            conn.commit()
            
            # Verify integrity
            ok = logger.verify_logs()
            if not ok:
                blocked += 1
            else:
                bypassed += 1
        except Exception:
            blocked += 1
    
    conn.close()
    
    return {
        'blocked': blocked,
        'bypassed': bypassed,
        'resistance_rate': blocked / sample_n if sample_n else 0.0,
        'timelock_delay': timelock_delay
    }


def scalability_with_risk_distribution(dataset: List[Tuple[str, str]], 
                                     high_risk_ratio: float = 0.5,
                                     timelock_delay: int = 15) -> Dict[str, Any]:
    """Test scalability with realistic risk distribution and timelock"""
    start_time = time.time()
    count = 0
    high_risk_count = 0
    
    cut = int(len(dataset) * high_risk_ratio)
    
    for i, (prompt, _) in enumerate(dataset):
        if i < cut:
            # High-risk operations with timelock
            enforce_timelock(timelock_delay)
            log_id = logger.log_interaction('eval_user', prompt, 'resp', risk_level='high')
            logger.sign_log_as_admin(log_id, 'admin')
            logger.sign_log_as_admin(log_id, 'admin2')
            high_risk_count += 1
        else:
            # Low-risk operations (no timelock)
            logger.log_interaction('eval_user', prompt, 'resp', risk_level='low')
        
        count += 1
    
    duration = time.time() - start_time
    
    return {
        'total_processed': count,
        'high_risk_count': high_risk_count,
        'duration_seconds': duration,
        'throughput_rpm': (count / duration) * 60.0 if duration > 0 else 0.0,
        'high_risk_throughput_rpm': (high_risk_count / duration) * 60.0 if duration > 0 else 0.0,
        'timelock_delay': timelock_delay
    }


def generate_latex_tables(results: Dict[str, Dict[str, Any]]) -> str:
    """Generate LaTeX tables from evaluation results"""
    latex_content = []
    
    # Main metrics table
    latex_content.append("\\begin{table}[h!]")
    latex_content.append("\\centering")
    latex_content.append("\\caption{Anti-Collusion Evaluation Results Across Dataset Sizes}")
    latex_content.append("\\label{tab:anticollusion_results}")
    latex_content.append("\\begin{tabular}{|l|c|c|c|c|}")
    latex_content.append("\\hline")
    latex_content.append("\\textbf{Metric} & \\textbf{4K} & \\textbf{6K} & \\textbf{50K} & \\textbf{200K} \\\\")
    latex_content.append("\\hline")
    
    metrics = ['collusion_detection_rate', 'false_positive_rate', 'tamper_resistance', 'latency_ms', 'throughput_rpm']
    metric_labels = ['Detection Rate', 'False Positive Rate', 'Tamper Resistance', 'Latency (ms)', 'Throughput (RPM)']
    
    for metric, label in zip(metrics, metric_labels):
        row = f"\\textbf{{{label}}}"
        for size in ['4k', '6k', '50k', '200k']:
            if size in results and metric in results[size]:
                value = results[size][metric]
                if metric in ['collusion_detection_rate', 'false_positive_rate', 'tamper_resistance']:
                    row += f" & {value:.3f}"
                elif metric == 'latency_ms':
                    row += f" & {value:.2f}"
                else:
                    row += f" & {value:.0f}"
            else:
                row += " & N/A"
        row += " \\\\"
        latex_content.append(row)
    
    latex_content.append("\\hline")
    latex_content.append("\\end{tabular}")
    latex_content.append("\\end{table}")
    
    # Timelock analysis table
    if any('timelock_delay' in results.get(size, {}) for size in results):
        latex_content.append("\n\\begin{table}[h!]")
        latex_content.append("\\centering")
        latex_content.append("\\caption{Timelock Impact on High-Risk Operations}")
        latex_content.append("\\label{tab:timelock_impact}")
        latex_content.append("\\begin{tabular}{|l|c|c|c|}")
        latex_content.append("\\hline")
        latex_content.append("\\textbf{Timelock (s)} & \\textbf{Detection Rate} & \\textbf{Latency (ms)} & \\textbf{Throughput (RPM)} \\\\")
        latex_content.append("\\hline")
        
        for delay in TIMELOCK_DELAYS:
            if '6k' in results and 'timelock_analysis' in results['6k']:
                analysis = results['6k']['timelock_analysis'].get(str(delay), {})
                detection = analysis.get('detection_rate', 0)
                latency = analysis.get('avg_latency_ms', 0)
                throughput = analysis.get('throughput_rpm', 0)
                latex_content.append(f"{delay} & {detection:.3f} & {latency:.2f} & {throughput:.0f} \\\\")
        
        latex_content.append("\\hline")
        latex_content.append("\\end{tabular}")
        latex_content.append("\\end{table}")
    
    return "\n".join(latex_content)


def generate_latex_figures(results: Dict[str, Dict[str, Any]]) -> str:
    """Generate LaTeX figure references"""
    latex_content = []
    
    latex_content.append("\\begin{figure}[h!]")
    latex_content.append("\\centering")
    latex_content.append("\\includegraphics[width=0.8\\textwidth]{results_anticollusion/anticollusion_summary.png}")
    latex_content.append("\\caption{Anti-Collusion Metrics Summary}")
    latex_content.append("\\label{fig:anticollusion_summary}")
    latex_content.append("\\end{figure}")
    
    return "\n".join(latex_content)


def write_results(outdir: str, results: Dict[str, Any], size: str) -> None:
    """Write results for a specific dataset size"""
    os.makedirs(outdir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(outdir, f'anticollusion_{size}_{timestamp}.csv')
    json_path = os.path.join(outdir, f'anticollusion_{size}_{timestamp}.json')
    
    # Write CSV
    with open(csv_path, 'w', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['metric', 'value', 'details'])
        for k, v in results.items():
            if isinstance(v, dict):
                w.writerow([k, str(v), json.dumps(v)])
            else:
                w.writerow([k, v, ''])
    
    # Write JSON
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results for {size} written to {csv_path} and {json_path}")


def create_aggregate_visualization(all_results: Dict[str, Dict[str, Any]], outdir: str):
    """Create comprehensive visualization of all results"""
    # Prepare data for plotting
    sizes = list(all_results.keys())
    metrics = ['collusion_detection_rate', 'false_positive_rate', 'tamper_resistance']
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Anti-Collusion Evaluation: Multi-Dataset Analysis', fontsize=16)
    
    # Metric comparison across datasets
    ax1 = axes[0, 0]
    x = range(len(sizes))
    width = 0.25
    
    for i, metric in enumerate(metrics):
        values = [all_results[size].get(metric, 0) for size in sizes]
        ax1.bar([xi + i*width for xi in x], values, width, label=metric.replace('_', ' ').title())
    
    ax1.set_xlabel('Dataset Size')
    ax1.set_ylabel('Rate')
    ax1.set_title('Detection Metrics by Dataset')
    ax1.set_xticks([xi + width for xi in x])
    ax1.set_xticklabels(sizes)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Latency comparison
    ax2 = axes[0, 1]
    latencies = [all_results[size].get('latency_ms', 0) for size in sizes]
    ax2.bar(sizes, latencies, color='skyblue')
    ax2.set_xlabel('Dataset Size')
    ax2.set_ylabel('Latency (ms)')
    ax2.set_title('Processing Latency by Dataset')
    ax2.grid(True, alpha=0.3)
    
    # Throughput comparison
    ax3 = axes[1, 0]
    throughputs = [all_results[size].get('throughput_rpm', 0) for size in sizes]
    ax3.bar(sizes, throughputs, color='lightgreen')
    ax3.set_xlabel('Dataset Size')
    ax3.set_ylabel('Throughput (RPM)')
    ax3.set_title('Processing Throughput by Dataset')
    ax3.grid(True, alpha=0.3)
    
    # Risk threshold analysis (if available)
    ax4 = axes[1, 1]
    if '6k' in all_results and 'risk_analysis' in all_results['6k']:
        risk_data = all_results['6k']['risk_analysis']
        thresholds = list(risk_data.keys())
        detection_rates = [risk_data[t]['detection_rate'] for t in thresholds]
        ax4.plot(thresholds, detection_rates, 'o-', color='red', linewidth=2, markersize=8)
        ax4.set_xlabel('Risk Threshold')
        ax4.set_ylabel('Detection Rate')
        ax4.set_title('Detection Rate vs Risk Threshold')
        ax4.grid(True, alpha=0.3)
    else:
        ax4.text(0.5, 0.5, 'Risk Analysis\nNot Available', ha='center', va='center', transform=ax4.transAxes)
        ax4.set_title('Risk Analysis')
    
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, 'anticollusion_multi_dataset_analysis.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Multi-dataset visualization saved to {outdir}/anticollusion_multi_dataset_analysis.png")


def main():
    """Main evaluation function"""
    all_results = {}
    
    for size in ['4k', '6k', '50k', '200k']:
        print(f"\n=== Evaluating {size} dataset ===")
        
        # Load dataset
        data = load_dataset(size)
        if not data:
            print(f"Skipping {size} - no data found")
            continue
        
        # Reset database for clean evaluation
        reset_db()
        
        # Sample size based on dataset
        sample_n = min(len(data), 1000 if size in ['4k', '6k'] else 500)
        
        # Basic metrics
        cdr = high_risk_collusion_detection(data, sample_n, risk_threshold=0.8, timelock_delay=15)
        fpr = false_positive_rate(data, risk_threshold=0.8)
        tr = tamper_resistance_with_timelock(data, min(100, sample_n), timelock_delay=15)
        sc = scalability_with_risk_distribution(data, high_risk_ratio=0.5, timelock_delay=15)
        
        # Risk threshold analysis (for 6k dataset)
        risk_analysis = {}
        if size == '6k':
            for threshold in HIGH_RISK_THRESHOLDS:
                risk_analysis[str(threshold)] = high_risk_collusion_detection(
                    data, min(300, sample_n), risk_threshold=threshold, timelock_delay=15
                )
        
        # Timelock analysis (for 6k dataset)
        timelock_analysis = {}
        if size == '6k':
            for delay in TIMELOCK_DELAYS:
                timelock_analysis[str(delay)] = high_risk_collusion_detection(
                    data, min(300, sample_n), risk_threshold=0.8, timelock_delay=delay
                )
        
        # Compile results
        results = {
            'collusion_detection_rate': cdr['detection_rate'],
            'false_positive_rate': fpr,
            'tamper_resistance': tr['resistance_rate'],
            'latency_ms': cdr['avg_latency_ms'],
            'throughput_rpm': sc['throughput_rpm'],
            'sample_size': sample_n,
            'risk_analysis': risk_analysis,
            'timelock_analysis': timelock_analysis,
            'detailed_metrics': {
                'collusion_detection': cdr,
                'tamper_resistance': tr,
                'scalability': sc
            }
        }
        
        all_results[size] = results
        write_results(OUTDIR, results, size)
        
        print(f"{size} evaluation complete:")
        print(f"  Detection Rate: {results['collusion_detection_rate']:.3f}")
        print(f"  False Positive Rate: {results['false_positive_rate']:.3f}")
        print(f"  Tamper Resistance: {results['tamper_resistance']:.3f}")
        print(f"  Latency: {results['latency_ms']:.2f} ms")
        print(f"  Throughput: {results['throughput_rpm']:.0f} RPM")
    
    # Create aggregate visualization
    create_aggregate_visualization(all_results, OUTDIR)
    
    # Generate LaTeX content
    latex_tables = generate_latex_tables(all_results)
    latex_figures = generate_latex_figures(all_results)
    
    # Write LaTeX content
    latex_path = os.path.join(OUTDIR, 'anticollusion_latex.tex')
    with open(latex_path, 'w', encoding='utf-8') as f:
        f.write("\\documentclass{article}\n")
        f.write("\\usepackage{graphicx}\n")
        f.write("\\usepackage{booktabs}\n")
        f.write("\\usepackage{float}\n")
        f.write("\\title{Anti-Collusion Evaluation Results}\n")
        f.write("\\author{LLM Defense System}\n")
        f.write("\\date{\\today}\n")
        f.write("\\begin{document}\n")
        f.write("\\maketitle\n")
        f.write("\n\\section{Results Summary}\n")
        f.write("Comprehensive evaluation of anti-collusion safeguards across multiple dataset sizes.\n")
        f.write("\n" + latex_tables + "\n")
        f.write("\n" + latex_figures + "\n")
        f.write("\\end{document}\n")
    
    print(f"\nLaTeX document written to {latex_path}")
    
    # Write aggregate CSV
    aggregate_path = os.path.join(OUTDIR, 'anticollusion_all_datasets.csv')
    with open(aggregate_path, 'w', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['dataset_size', 'collusion_detection_rate', 'false_positive_rate', 
                   'tamper_resistance', 'latency_ms', 'throughput_rpm', 'sample_size'])
        for size, results in all_results.items():
            w.writerow([
                size,
                results['collusion_detection_rate'],
                results['false_positive_rate'],
                results['tamper_resistance'],
                results['latency_ms'],
                results['throughput_rpm'],
                results['sample_size']
            ])
    
    print(f"Aggregate results written to {aggregate_path}")
    print("\nEnhanced anti-collusion evaluation complete!")


if __name__ == '__main__':
    main()
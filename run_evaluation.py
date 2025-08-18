#!/usr/bin/env python3
"""
Fixed version with guaranteed plot generation
"""

from evaluation_pipeline import AdvancedEvaluationPipeline
import argparse
import os
import sys
from datetime import datetime
try:
    import pandas as pd  # type: ignore
except Exception:
    pd = None
import matplotlib
matplotlib.use('Agg')  # Set backend before pyplot import
import matplotlib.pyplot as plt


class PlotGenerator:
    """Handles all plot generation with guaranteed output"""

    @staticmethod
    def generate_all_plots(results: dict, output_dir: str):
        """Generate all possible plots from results"""
        os.makedirs(output_dir, exist_ok=True)

        # 1. Performance Metrics Plot
        if 'metrics' in results:
            PlotGenerator._plot_metrics(results['metrics'], output_dir)

        # 2. Confusion Matrix
        if 'confusion_matrix' in results:
            cm = results['confusion_matrix']
            if all(k in cm for k in ['y_true', 'y_pred', 'labels']):
                PlotGenerator._plot_confusion_matrix(
                    cm['y_true'], cm['y_pred'], cm['labels'], output_dir)

        # 3. Latency Plot
        if 'latency' in results:
            PlotGenerator._plot_latency(results['latency'], output_dir)

    @staticmethod
    def _plot_metrics(metrics: dict, output_dir: str):
        """Generate metrics comparison plot"""
        try:
            methods = list(metrics.keys())
            acc = [metrics[m].get('accuracy', 0.0) for m in methods]
            prec = [metrics[m].get('precision', 0.0) for m in methods]
            rec = [metrics[m].get('recall', 0.0) for m in methods]
            f1 = [metrics[m].get('f1', 0.0) for m in methods]

            plt.figure(figsize=(12, 8))
            # Accuracy
            plt.subplot(2, 2, 1)
            plt.bar(methods, acc)
            plt.title('Accuracy Comparison')
            plt.ylabel('Accuracy')
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.6)
            # Precision
            plt.subplot(2, 2, 2)
            plt.bar(methods, prec)
            plt.title('Precision Comparison')
            plt.ylabel('Precision')
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.6)
            # Recall
            plt.subplot(2, 2, 3)
            plt.bar(methods, rec)
            plt.title('Recall Comparison')
            plt.ylabel('Recall')
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.6)
            # F1
            plt.subplot(2, 2, 4)
            plt.bar(methods, f1)
            plt.title('F1 Comparison')
            plt.ylabel('F1')
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.6)

            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'performance_metrics.png'))
            plt.close()
            print("✓ Generated performance metrics plot")
        except Exception as e:
            print(f"⚠️ Could not generate metrics plot: {e}")

    @staticmethod
    def _plot_confusion_matrix(y_true, y_pred, labels, output_dir: str):
        """Generate confusion matrix plot"""
        try:
            from collections import Counter
            # Build confusion counts
            index = {label: i for i, label in enumerate(labels)}
            size = len(labels)
            cm = [[0 for _ in range(size)] for _ in range(size)]
            for yt, yp in zip(y_true, y_pred):
                if yt in index and yp in index:
                    cm[index[yt]][index[yp]] += 1

            plt.figure(figsize=(10, 8))
            plt.imshow(cm, interpolation='nearest', cmap='Blues')
            plt.title('Confusion Matrix')
            plt.colorbar()
            tick_marks = range(len(labels))
            plt.xticks(tick_marks, labels, rotation=45)
            plt.yticks(tick_marks, labels)
            # Annotate
            for i in range(size):
                for j in range(size):
                    plt.text(j, i, str(cm[i][j]), ha='center', va='center', color='black')
            plt.ylabel('Actual')
            plt.xlabel('Predicted')
            plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
            plt.close()
            print("✓ Generated confusion matrix plot")
        except Exception as e:
            print(f"⚠️ Could not generate confusion matrix: {e}")

    @staticmethod
    def _plot_latency(latency: dict, output_dir: str):
        """Generate latency comparison plot"""
        try:
            plt.figure(figsize=(10, 6))
            pd.Series(latency).plot(kind='bar')
            plt.title('Latency Comparison (ms)')
            plt.ylabel('Milliseconds')
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.6)
            plt.savefig(os.path.join(output_dir, 'latency_comparison.png'))
            plt.close()
            print("✓ Generated latency comparison plot")
        except Exception as e:
            print(f"⚠️ Could not generate latency plot: {e}")


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Run ZKP LLM evaluation')
    parser.add_argument('--dataset', '-d', type=str, help='Dataset path')
    parser.add_argument('--output', '-o', type=str, default='results',
                        help='Output directory')
    args = parser.parse_args()

    # Setup output directory
    os.makedirs(args.output, exist_ok=True)

    # Run evaluation
    print("🚀 Running evaluation...")
    pipeline = AdvancedEvaluationPipeline(args.dataset)
    # Get raw results per method
    all_results = pipeline.run_evaluation()

    if not all_results:
        print("❌ No results returned from evaluation!")
        sys.exit(1)

    # Compute metrics per method
    metrics = {method: pipeline.calculate_metrics(results)
               for method, results in all_results.items()}

    # Build confusion matrix from ZKP Framework results
    zkp_results = all_results.get('ZKP Framework', [])
    y_true = [r.true_label for r in zkp_results]
    y_pred = [r.predicted_label for r in zkp_results]
    labels = ['safe', 'adversarial']

    # Build latency dict (ms)
    latency = {method: (metrics[method].get('avg_detection_time', 0.0) * 1000.0)
               for method in metrics}

    results = {
        'metrics': metrics,
        'confusion_matrix': {
            'y_true': y_true,
            'y_pred': y_pred,
            'labels': labels,
        },
        'latency': latency,
    }

    # Generate plots
    print("\n📊 Generating visualizations...")
    PlotGenerator.generate_all_plots(results, args.output)

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pd.DataFrame(results['metrics']).to_csv(
        os.path.join(args.output, f'metrics_{timestamp}.csv'))

    print(f"\n✅ Done! Results saved to {args.output}")


if __name__ == '__main__':
    # Configure plotting style
    try:
        plt.style.use('seaborn-v0_8')
    except Exception:
        plt.style.use('ggplot')
    main()
 #!/usr/bin/env python3
"""
Simple runner for the Advanced Evaluation Pipeline
"""

from evaluation_pipeline import AdvancedEvaluationPipeline
import argparse

def main():
    print("🔬 ZKP-Based LLM Security Evaluation")
    print("=" * 50)
    print("This will evaluate your ZKP framework against multiple baselines")
    print("and provide comprehensive analysis with visualizations.")
    print()
    
    parser = argparse.ArgumentParser(description="Run evaluation with optional external dataset")
    parser.add_argument("--dataset", "-d", type=str, default=None, help="Path to JSON/CSV dataset (prompt,label)")
    args = parser.parse_args()
    
    # Initialize and run evaluation
    pipeline = AdvancedEvaluationPipeline(dataset_path=args.dataset)
    pipeline.run_complete_evaluation()
    
    print("\n🎉 Evaluation complete! Check the generated files:")
    print("  • evaluation_results.png - Visualizations")
    print("  • evaluation_metrics_*.csv - Performance metrics")
    print("  • detailed_results_*.csv - Detailed results")

if __name__ == "__main__":
    main()
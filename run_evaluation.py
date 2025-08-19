#!/usr/bin/env python3
"""
Enhanced Evaluation Pipeline with Beautiful Visualizations
Features modern color schemes, enhanced styling, and improved readability
"""

import os
import sys
import json
import argparse
from datetime import datetime
try:
    import pandas as pd
except ImportError:
    pd = None
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import seaborn as sns
    from matplotlib.colors import LinearSegmentedColormap
except ImportError:
    plt = None
    sns = None

# Import the evaluation pipeline
try:
    from evaluation_pipeline import AdvancedEvaluationPipeline
except ImportError:
    print("⚠️ Could not import AdvancedEvaluationPipeline. Make sure evaluation_pipeline.py is available.")
    AdvancedEvaluationPipeline = None

class PlotGenerator:
    """Enhanced plot generator with beautiful color schemes and modern styling"""
    
    # Beautiful color palettes for different chart types
    BAR_COLORS = {
        'performance': ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'],
        'metrics': ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe'],
        'latency': ['#a8edea', '#fed6e3', '#ffecd2', '#fcb69f', '#ff9a9e', '#fecfef']
    }
    
    PIE_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#FF8A80', '#82B1FF']
    
    LINE_COLORS = ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#43e97b', '#38f9d7']
    
    HEATMAP_CMAP = 'RdYlBu_r'  # Red-Yellow-Blue reversed for better contrast
    
    @staticmethod
    def setup_modern_style():
        """Set up modern matplotlib styling with beautiful aesthetics"""
        if plt is None:
            return
            
        # Set modern style
        plt.style.use('default')
        
        # Configure seaborn for beautiful plots
        if sns is not None:
            sns.set_palette("husl")
            sns.set_style("whitegrid", {
                'axes.facecolor': '#f8f9fa',
                'axes.edgecolor': '#dee2e6',
                'grid.color': '#e9ecef',
                'grid.linestyle': '--',
                'grid.alpha': 0.7
            })
        
        # Set font properties for better readability
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10
        plt.rcParams['legend.fontsize'] = 10
        plt.rcParams['figure.titlesize'] = 16

    @staticmethod
    def generate_all_plots(results: dict, output_dir: str):
        """Generate all possible plots from results with enhanced styling"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Set up modern styling
        PlotGenerator.setup_modern_style()

        # 1. Performance Metrics Plot (Enhanced)
        if 'metrics' in results:
            PlotGenerator._plot_metrics_enhanced(results['metrics'], output_dir)

        # 2. Confusion Matrix (Enhanced)
        if 'confusion_matrix' in results:
            cm = results['confusion_matrix']
            if all(k in cm for k in ['y_true', 'y_pred', 'labels']):
                PlotGenerator._plot_confusion_matrix_enhanced(
                    cm['y_true'], cm['y_pred'], cm['labels'], output_dir)

        # 3. Latency Plot (Enhanced)
        if 'latency' in results:
            PlotGenerator._plot_latency_enhanced(results['latency'], output_dir)
            
        # 4. New: Pie Chart for Method Distribution
        if 'metrics' in results:
            PlotGenerator._plot_method_distribution_pie(results['metrics'], output_dir)
            
        # 5. New: Line Chart for Performance Trends
        if 'metrics' in results:
            PlotGenerator._plot_performance_trends(results['metrics'], output_dir)

    @staticmethod
    def _plot_metrics_enhanced(metrics: dict, output_dir: str):
        """Generate enhanced metrics comparison plot with beautiful colors"""
        try:
            methods = list(metrics.keys())
            acc = [metrics[m].get('accuracy', 0.0) for m in methods]
            prec = [metrics[m].get('precision', 0.0) for m in methods]
            rec = [metrics[m].get('recall', 0.0) for m in methods]
            f1 = [metrics[m].get('f1', 0.0) for m in methods]

            # Create figure with enhanced styling
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Performance Metrics Comparison', fontsize=18, fontweight='bold', 
                        color='#2c3e50', y=0.95)
            
            # Custom colors for each metric
            colors = PlotGenerator.BAR_COLORS['metrics']
            
            # Accuracy
            ax1 = axes[0, 0]
            bars1 = ax1.bar(methods, acc, color=colors[0], alpha=0.8, edgecolor='white', linewidth=2)
            ax1.set_title('Accuracy Comparison', fontweight='bold', color='#2c3e50')
            ax1.set_ylabel('Accuracy Score', fontweight='bold')
            ax1.set_xticklabels(methods, rotation=45, ha='right')
            ax1.grid(True, alpha=0.3, linestyle='--')
            ax1.set_ylim(0, 1.1)
            
            # Add value labels on bars
            for bar, value in zip(bars1, acc):
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2, height + 0.02,
                        f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
            
            # Precision
            ax2 = axes[0, 1]
            bars2 = ax2.bar(methods, prec, color=colors[1], alpha=0.8, edgecolor='white', linewidth=2)
            ax2.set_title('Precision Comparison', fontweight='bold', color='#2c3e50')
            ax2.set_ylabel('Precision Score', fontweight='bold')
            ax2.set_xticklabels(methods, rotation=45, ha='right')
            ax2.grid(True, alpha=0.3, linestyle='--')
            ax2.set_ylim(0, 1.1)
            
            for bar, value in zip(bars2, prec):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2, height + 0.02,
                        f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
            
            # Recall
            ax3 = axes[1, 0]
            bars3 = ax3.bar(methods, rec, color=colors[2], alpha=0.8, edgecolor='white', linewidth=2)
            ax3.set_title('Recall Comparison', fontweight='bold', color='#2c3e50')
            ax3.set_ylabel('Recall Score', fontweight='bold')
            ax3.set_xlabel('Detection Methods', fontweight='bold')
            ax3.set_xticklabels(methods, rotation=45, ha='right')
            ax3.grid(True, alpha=0.3, linestyle='--')
            ax3.set_ylim(0, 1.1)
            
            for bar, value in zip(bars3, rec):
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width()/2, height + 0.02,
                        f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
            
            # F1
            ax4 = axes[1, 1]
            bars4 = ax4.bar(methods, f1, color=colors[3], alpha=0.8, edgecolor='white', linewidth=2)
            ax4.set_title('F1 Score Comparison', fontweight='bold', color='#2c3e50')
            ax4.set_ylabel('F1 Score', fontweight='bold')
            ax4.set_xlabel('Detection Methods', fontweight='bold')
            ax4.set_xticklabels(methods, rotation=45, ha='right')
            ax4.grid(True, alpha=0.3, linestyle='--')
            ax4.set_ylim(0, 1.1)
            
            for bar, value in zip(bars4, f1):
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2, height + 0.02,
                        f'{value:.3f}', ha='center', va='bottom', fontweight='bold')

            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'performance_metrics_enhanced.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated enhanced performance metrics plot")
        except Exception as e:
            print(f"⚠️ Could not generate enhanced metrics plot: {e}")

    @staticmethod
    def _plot_confusion_matrix_enhanced(y_true, y_pred, labels, output_dir: str):
        """Generate enhanced confusion matrix plot with beautiful colors"""
        try:
            from collections import Counter
            # Build confusion counts
            index = {label: i for i, label in enumerate(labels)}
            size = len(labels)
            cm = [[0 for _ in range(size)] for _ in range(size)]
            for yt, yp in zip(y_true, y_pred):
                if yt in index and yp in index:
                    cm[index[yt]][index[yp]] += 1

            # Create enhanced confusion matrix
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Use custom colormap for better visualization
            colors = ['#f7f7f7', '#d1e5c0', '#92c5de', '#4393c3', '#2166ac']
            n_bins = 100
            cmap = LinearSegmentedColormap.from_list("custom", colors, N=n_bins)
            
            im = ax.imshow(cm, interpolation='nearest', cmap=cmap, aspect='auto')
            ax.set_title('Confusion Matrix', fontsize=16, fontweight='bold', color='#2c3e50', pad=20)
            
            # Add colorbar
            cbar = plt.colorbar(im, ax=ax, shrink=0.8)
            cbar.set_label('Count', fontweight='bold')
            
            tick_marks = range(len(labels))
            ax.set_xticks(tick_marks)
            ax.set_yticks(tick_marks)
            ax.set_xticklabels(labels, rotation=45, ha='right')
            ax.set_yticklabels(labels)
            
            # Annotate with enhanced styling
            for i in range(size):
                for j in range(size):
                    color = 'white' if cm[i][j] > max(max(row) for row in cm) / 2 else 'black'
                    ax.text(j, i, str(cm[i][j]), ha='center', va='center', 
                           color=color, fontweight='bold', fontsize=12)
            
            ax.set_ylabel('Actual Label', fontweight='bold', fontsize=12)
            ax.set_xlabel('Predicted Label', fontweight='bold', fontsize=12)
            
            # Add grid for better readability
            ax.grid(False)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'confusion_matrix_enhanced.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated enhanced confusion matrix plot")
        except Exception as e:
            print(f"⚠️ Could not generate enhanced confusion matrix: {e}")

    @staticmethod
    def _plot_latency_enhanced(latency: dict, output_dir: str):
        """Generate enhanced latency comparison plot with beautiful colors"""
        try:
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Use custom colors for latency bars
            colors = PlotGenerator.BAR_COLORS['latency']
            methods = list(latency.keys())
            values = list(latency.values())
            
            # Create gradient effect by varying alpha
            bars = ax.bar(methods, values, color=colors[:len(methods)], 
                         alpha=0.8, edgecolor='white', linewidth=2)
            
            ax.set_title('Latency Comparison', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            ax.set_ylabel('Latency (ms)', fontweight='bold', fontsize=12)
            ax.set_xlabel('Detection Methods', fontweight='bold', fontsize=12)
            ax.set_xticklabels(methods, rotation=45, ha='right')
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height + max(values) * 0.01,
                       f'{value:.1f}ms', ha='center', va='bottom', fontweight='bold')
            
            # Enhanced grid
            ax.grid(True, alpha=0.3, linestyle='--', color='#bdc3c7')
            ax.set_axisbelow(True)
            
            # Set y-axis to start from 0
            ax.set_ylim(0, max(values) * 1.1)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'latency_comparison_enhanced.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated enhanced latency comparison plot")
        except Exception as e:
            print(f"⚠️ Could not generate enhanced latency plot: {e}")

    @staticmethod
    def _plot_method_distribution_pie(metrics: dict, output_dir: str):
        """Generate beautiful pie chart showing method distribution"""
        try:
            # Calculate average performance for each method
            method_scores = {}
            for method, data in metrics.items():
                avg_score = (data.get('accuracy', 0) + data.get('precision', 0) + 
                           data.get('recall', 0) + data.get('f1', 0)) / 4
                method_scores[method] = avg_score
            
            # Sort by performance
            sorted_methods = sorted(method_scores.items(), key=lambda x: x[1], reverse=True)
            methods, scores = zip(*sorted_methods)
            
            # Create pie chart
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Use custom colors
            colors = PlotGenerator.PIE_COLORS[:len(methods)]
            
            # Create pie chart with enhanced styling
            wedges, texts, autotexts = ax.pie(scores, labels=methods, autopct='%1.1f%%',
                                             colors=colors, startangle=90, 
                                             wedgeprops={'edgecolor': 'white', 'linewidth': 2})
            
            # Enhance text styling
            for text in texts:
                text.set_fontweight('bold')
                text.set_fontsize(11)
            
            for autotext in autotexts:
                autotext.set_fontweight('bold')
                autotext.set_color('white')
                autotext.set_fontsize(10)
            
            ax.set_title('Method Performance Distribution', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            
            # Add legend
            legend_elements = [mpatches.Patch(color=color, label=f'{method}: {score:.3f}')
                             for method, score, color in zip(methods, scores, colors)]
            ax.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0, 0.5, 1))
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'method_distribution_pie.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated method distribution pie chart")
        except Exception as e:
            print(f"⚠️ Could not generate pie chart: {e}")

    @staticmethod
    def _plot_performance_trends(metrics: dict, output_dir: str):
        """Generate line chart showing performance trends across methods"""
        try:
            # Prepare data for line chart
            methods = list(metrics.keys())
            metrics_list = ['accuracy', 'precision', 'recall', 'f1']
            
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Use custom line colors
            colors = PlotGenerator.LINE_COLORS[:len(metrics_list)]
            
            # Plot each metric as a line
            for i, metric in enumerate(metrics_list):
                values = [metrics[method].get(metric, 0) for method in methods]
                ax.plot(methods, values, marker='o', linewidth=3, markersize=8,
                       color=colors[i], label=metric.title(), alpha=0.8)
            
            ax.set_title('Performance Trends Across Methods', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            ax.set_xlabel('Detection Methods', fontweight='bold', fontsize=12)
            ax.set_ylabel('Score', fontweight='bold', fontsize=12)
            ax.set_xticklabels(methods, rotation=45, ha='right')
            
            # Enhanced grid and styling
            ax.grid(True, alpha=0.3, linestyle='--', color='#bdc3c7')
            ax.set_axisbelow(True)
            ax.set_ylim(0, 1.1)
            
            # Add legend
            ax.legend(loc='upper right', framealpha=0.9, fancybox=True, shadow=True)
            
            # Add value labels on points
            for method_idx, method in enumerate(methods):
                for metric_idx, metric in enumerate(metrics_list):
                    value = metrics[method].get(metric, 0)
                    ax.annotate(f'{value:.3f}', 
                               (method_idx, value),
                               textcoords="offset points",
                               xytext=(0, 10),
                               ha='center',
                               fontsize=9,
                               fontweight='bold')
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'performance_trends_line.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated performance trends line chart")
        except Exception as e:
            print(f"⚠️ Could not generate line chart: {e}")


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
    
    if AdvancedEvaluationPipeline is None:
        print("❌ AdvancedEvaluationPipeline not available. Creating sample data for visualization demo...")
        # Create sample data for visualization demo
        all_results = {
            'ZKP Framework': [
                type('DetectionResult', (), {
                    'true_label': 'safe' if i % 2 == 0 else 'adversarial',
                    'predicted_label': 'safe' if i % 2 == 0 else 'adversarial',
                    'confidence': 0.8 + (i * 0.1) % 0.2,
                    'detection_time': 0.045 + (i * 0.01) % 0.02
                })() for i in range(100)
            ],
            'Regex Baseline': [
                type('DetectionResult', (), {
                    'true_label': 'safe' if i % 3 == 0 else 'adversarial',
                    'predicted_label': 'safe' if i % 3 == 0 else 'adversarial',
                    'confidence': 0.7 + (i * 0.1) % 0.3,
                    'detection_time': 0.013 + (i * 0.001) % 0.005
                })() for i in range(100)
            ],
            'Semantic Classifier': [
                type('DetectionResult', (), {
                    'true_label': 'safe' if i % 4 == 0 else 'adversarial',
                    'predicted_label': 'safe' if i % 4 == 0 else 'adversarial',
                    'confidence': 0.85 + (i * 0.1) % 0.15,
                    'detection_time': 0.157 + (i * 0.01) % 0.02
                })() for i in range(100)
            ]
        }
    else:
        pipeline = AdvancedEvaluationPipeline(args.dataset)
        # Get raw results per method
        all_results = pipeline.run_evaluation()

    if not all_results:
        print("❌ No results returned from evaluation!")
        sys.exit(1)

    # Compute metrics per method
    if AdvancedEvaluationPipeline is not None:
        metrics = {method: pipeline.calculate_metrics(results)
                   for method, results in all_results.items()}
    else:
        # Simple metrics calculation for demo
        metrics = {}
        for method, results in all_results.items():
            total = len(results)
            correct = sum(1 for r in results if r.true_label == r.predicted_label)
            accuracy = correct / total if total > 0 else 0
            
            # Simple precision/recall calculation
            true_positives = sum(1 for r in results if r.true_label == 'adversarial' and r.predicted_label == 'adversarial')
            predicted_positives = sum(1 for r in results if r.predicted_label == 'adversarial')
            actual_positives = sum(1 for r in results if r.true_label == 'adversarial')
            
            precision = true_positives / predicted_positives if predicted_positives > 0 else 0
            recall = true_positives / actual_positives if actual_positives > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            avg_time = sum(r.detection_time for r in results) / total if total > 0 else 0
            
            metrics[method] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'avg_detection_time': avg_time
            }

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
    # Configure plotting style only if matplotlib is available
    if plt is not None:
        try:
            plt.style.use('seaborn-v0_8')
        except Exception:
            try:
                plt.style.use('ggplot')
            except Exception:
                plt.style.use('default')
    main()
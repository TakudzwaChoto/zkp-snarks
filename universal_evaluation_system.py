#!/usr/bin/env python3
"""
Universal Evaluation System with Automatic Image Generation
Works with ANY dataset format and ALWAYS generates beautiful visualizations
"""

import os
import sys
import json
import csv
import argparse
from datetime import datetime
from pathlib import Path

# Import the evaluation pipeline
try:
    from evaluation_pipeline import AdvancedEvaluationPipeline
except ImportError:
    print("❌ Could not import AdvancedEvaluationPipeline. Make sure evaluation_pipeline.py is available.")
    sys.exit(1)

# Import visualization modules
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    import pandas as pd
    VISUALIZATION_AVAILABLE = True
except ImportError:
    print("⚠️ Visualization packages not available. Installing required packages...")
    VISUALIZATION_AVAILABLE = False

class UniversalEvaluator:
    """Universal evaluation system that works with any dataset and generates images"""
    
    def __init__(self):
        self.setup_visualization_style()
    
    def setup_visualization_style(self):
        """Setup beautiful visualization styling"""
        if not VISUALIZATION_AVAILABLE:
            return
            
        plt.style.use('default')
        sns.set_palette("husl")
        sns.set_style("whitegrid", {
            'axes.facecolor': '#f8f9fa',
            'axes.edgecolor': '#dee2e6',
            'grid.color': '#e9ecef',
            'grid.linestyle': '--',
            'grid.alpha': 0.7
        })
        
        plt.rcParams['font.size'] = 11
        plt.rcParams['axes.titlesize'] = 16
        plt.rcParams['axes.labelsize'] = 13
        plt.rcParams['xtick.labelsize'] = 11
        plt.rcParams['ytick.labelsize'] = 11
        plt.rcParams['legend.fontsize'] = 11
        plt.rcParams['figure.titlesize'] = 18
    
    def detect_dataset_format(self, dataset_path):
        """Automatically detect dataset format and convert if needed"""
        path = Path(dataset_path)
        
        if path.suffix.lower() == '.json':
            print(f"📁 Detected JSON dataset: {dataset_path}")
            return self.convert_json_to_csv(dataset_path)
        elif path.suffix.lower() == '.jsonl':
            print(f"📁 Detected JSONL dataset: {dataset_path}")
            return self.convert_jsonl_to_csv(dataset_path)
        elif path.suffix.lower() == '.csv':
            print(f"📁 Detected CSV dataset: {dataset_path}")
            return dataset_path
        else:
            print(f"❌ Unsupported dataset format: {path.suffix}")
            print("Supported formats: .json, .jsonl, .csv")
            sys.exit(1)
    
    def convert_json_to_csv(self, json_path):
        """Convert JSON dataset to clean CSV format"""
        csv_path = json_path.replace('.json', '_converted.csv')
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Auto-detect structure
                if data and isinstance(data[0], dict):
                    # Get all possible keys
                    all_keys = set()
                    for item in data:
                        all_keys.update(item.keys())
                    
                    # Find label column (common variations)
                    label_keys = ['label', 'true_label', 'class', 'category', 'target']
                    label_col = None
                    for key in label_keys:
                        if key in all_keys:
                            label_col = key
                            break
                    
                    if not label_col:
                        label_col = list(all_keys)[0]  # Use first key as label
                    
                    # Find prompt/text column
                    text_keys = ['prompt', 'text', 'input', 'sentence', 'content']
                    text_col = None
                    for key in text_keys:
                        if key in all_keys:
                            text_col = key
                            break
                    
                    if not text_col:
                        text_col = list(all_keys)[1] if len(all_keys) > 1 else list(all_keys)[0]
                    
                    # Write header
                    writer.writerow(['prompt', 'label'])
                    
                    # Write data
                    for item in data:
                        prompt = str(item.get(text_col, '')).strip()
                        label = str(item.get(label_col, '')).strip()
                        if prompt and label:
                            clean_prompt = ' '.join(prompt.split())
                            writer.writerow([clean_prompt, label])
                
                print(f"✅ Converted JSON to CSV: {csv_path}")
                return csv_path
                
        except Exception as e:
            print(f"❌ Error converting JSON: {e}")
            sys.exit(1)
    
    def convert_jsonl_to_csv(self, jsonl_path):
        """Convert JSONL dataset to clean CSV format"""
        csv_path = jsonl_path.replace('.jsonl', '_converted.csv')
        
        try:
            with open(jsonl_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['prompt', 'label'])
                
                # Process each line (JSONL format)
                for line in lines:
                    line = line.strip()
                    if line:
                        try:
                            item = json.loads(line)
                            
                            # Extract prompt and label
                            prompt = str(item.get('prompt', '')).strip()
                            label = str(item.get('label', '')).strip()
                            
                            # Map labels to our expected format
                            if label.lower() in ['malicious', 'adversarial', 'attack']:
                                label = 'adversarial'
                            elif label.lower() in ['benign', 'safe', 'normal']:
                                label = 'benign'
                            
                            if prompt and label:
                                clean_prompt = ' '.join(prompt.split())
                                writer.writerow([clean_prompt, label])
                                
                        except json.JSONDecodeError:
                            continue  # Skip invalid JSON lines
                
                print(f"✅ Converted JSONL to CSV: {csv_path}")
                return csv_path
                
        except Exception as e:
            print(f"❌ Error converting JSONL: {e}")
            sys.exit(1)
    
    def run_evaluation(self, dataset_path, output_dir):
        """Run complete evaluation with automatic image generation"""
        print("🚀 Starting Universal Evaluation System...")
        print("=" * 60)
        
        # Detect and convert dataset if needed
        clean_dataset_path = self.detect_dataset_format(dataset_path)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Run evaluation
        print(f"🔬 Running evaluation on: {clean_dataset_path}")
        pipeline = AdvancedEvaluationPipeline(clean_dataset_path)
        all_results = pipeline.run_evaluation()
        
        if not all_results:
            print("❌ No results returned from evaluation!")
            sys.exit(1)
        
        # Calculate metrics
        print("📊 Calculating metrics...")
        metrics = {}
        for method, results in all_results.items():
            metrics[method] = pipeline.calculate_metrics(results)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save metrics CSV
        metrics_file = os.path.join(output_dir, f'universal_metrics_{timestamp}.csv')
        self.save_metrics_csv(metrics, metrics_file)
        
        # Save detailed results
        detailed_file = os.path.join(output_dir, f'universal_detailed_{timestamp}.csv')
        self.save_detailed_results(all_results, detailed_file)
        
        # Generate visualizations
        if VISUALIZATION_AVAILABLE:
            print("🎨 Generating beautiful visualizations...")
            self.generate_all_visualizations(metrics, all_results, output_dir, timestamp)
        else:
            print("⚠️ Skipping visualizations (packages not available)")
        
        # Print summary
        self.print_evaluation_summary(metrics)
        
        print(f"\n✅ Universal evaluation completed!")
        print(f"📁 Results saved to: {output_dir}")
        
        return metrics, all_results
    
    def save_metrics_csv(self, metrics, output_file):
        """Save metrics to clean CSV"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write metrics
            methods = list(metrics.keys())
            writer.writerow(['Metric'] + methods)
            
            metric_names = ['precision', 'recall', 'f1', 'accuracy', 'specificity', 'sensitivity', 'avg_detection_time']
            for metric in metric_names:
                row = [metric]
                for method in methods:
                    row.append(metrics[method].get(metric, 0))
                writer.writerow(row)
            
            # Write confusion matrix data
            writer.writerow([])
            writer.writerow(['Confusion Matrix Data'])
            writer.writerow(['Method', 'True Positives', 'True Negatives', 'False Positives', 'False Negatives'])
            
            for method in methods:
                cm_data = metrics[method]
                writer.writerow([
                    method,
                    cm_data.get('true_positives', 0),
                    cm_data.get('true_negatives', 0),
                    cm_data.get('false_positives', 0),
                    cm_data.get('false_negatives', 0)
                ])
        
        print(f"✅ Metrics saved: {output_file}")
    
    def save_detailed_results(self, all_results, output_file):
        """Save detailed results to CSV"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Method', 'Prompt', 'True Label', 'Predicted Label', 'Confidence', 'Detection Time (ms)'])
            
            for method, results in all_results.items():
                for result in results:
                    writer.writerow([
                        method,
                        result.prompt[:100] + '...' if len(result.prompt) > 100 else result.prompt,
                        result.true_label,
                        result.predicted_label,
                        f"{result.confidence:.3f}",
                        f"{result.detection_time * 1000:.3f}"
                    ])
        
        print(f"✅ Detailed results saved: {output_file}")
    
    def generate_all_visualizations(self, metrics, all_results, output_dir, timestamp):
        """Generate all beautiful visualizations"""
        methods = list(metrics.keys())
        
        # 1. Performance Radar Chart
        self.create_performance_radar_chart(metrics, output_dir, timestamp)
        
        # 2. Confusion Matrix Heatmaps
        self.create_confusion_matrix_heatmaps(metrics, output_dir, timestamp)
        
        # 3. Metrics Comparison Bars
        self.create_metrics_comparison_bars(metrics, output_dir, timestamp)
        
        # 4. Performance Summary Table
        self.create_performance_summary_table(metrics, output_dir, timestamp)
        
        # 5. Detection Time Comparison
        self.create_detection_time_comparison(metrics, output_dir, timestamp)
        
        # 6. Performance Trends
        self.create_performance_trends(metrics, output_dir, timestamp)
    
    def create_performance_radar_chart(self, metrics, output_dir, timestamp):
        """Create performance radar chart"""
        try:
            fig, ax = plt.subplots(figsize=(12, 10), subplot_kw=dict(projection='polar'))
            
            radar_metrics = ['precision', 'recall', 'f1', 'accuracy']
            methods = list(metrics.keys())
            
            angles = np.linspace(0, 2 * np.pi, len(radar_metrics), endpoint=False).tolist()
            angles += angles[:1]
            
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
            
            for i, method in enumerate(methods):
                values = [metrics[method][metric] for metric in radar_metrics]
                values += values[:1]
                
                ax.plot(angles, values, 'o-', linewidth=3, markersize=8,
                       label=method, color=colors[i % len(colors)], alpha=0.8)
                ax.fill(angles, values, alpha=0.1, color=colors[i % len(colors)])
            
            ax.set_xticks(angles[:-1])
            ax.set_xticklabels([metric.upper() for metric in radar_metrics], fontsize=12, fontweight='bold')
            ax.set_ylim(0, 1.1)
            ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
            ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=10)
            ax.grid(True, alpha=0.3)
            ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=12)
            
            plt.title('Performance Radar Chart - Universal Evaluation', 
                      fontsize=18, fontweight='bold', pad=30, color='#2c3e50')
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'performance_radar_{timestamp}.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated performance radar chart")
        except Exception as e:
            print(f"⚠️ Could not generate radar chart: {e}")
    
    def create_confusion_matrix_heatmaps(self, metrics, output_dir, timestamp):
        """Create confusion matrix heatmaps"""
        try:
            methods = list(metrics.keys())
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Confusion Matrix Heatmaps - Universal Evaluation', 
                         fontsize=20, fontweight='bold', color='#2c3e50', y=0.95)
            
            for idx, method in enumerate(methods):
                row = idx // 2
                col = idx % 2
                ax = axes[row, col]
                
                cm_data = metrics[method]
                cm = np.array([[cm_data['true_negatives'], cm_data['false_positives']], 
                              [cm_data['false_negatives'], cm_data['true_positives']]])
                
                sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlBu_r', 
                           xticklabels=['Benign', 'Adversarial'],
                           yticklabels=['Benign', 'Adversarial'],
                           ax=ax, cbar_kws={'shrink': 0.8})
                
                ax.set_title(f'{method}', fontsize=14, fontweight='bold', color='#2c3e50')
                ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
                ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
                
                total = cm_data['true_positives'] + cm_data['true_negatives'] + cm_data['false_positives'] + cm_data['false_negatives']
                accuracy = (cm_data['true_positives'] + cm_data['true_negatives']) / total
                precision = cm_data['true_positives'] / (cm_data['true_positives'] + cm_data['false_positives']) if (cm_data['true_positives'] + cm_data['false_positives']) > 0 else 0
                recall = cm_data['true_positives'] / (cm_data['true_positives'] + cm_data['false_negatives']) if (cm_data['true_positives'] + cm_data['false_negatives']) > 0 else 0
                
                textstr = f'Accuracy: {accuracy:.3f}\nPrecision: {precision:.3f}\nRecall: {recall:.3f}'
                props = dict(boxstyle='round', facecolor='wheat', alpha=0.8)
                ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=10,
                        verticalalignment='top', bbox=props)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'confusion_matrix_{timestamp}.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated confusion matrix heatmaps")
        except Exception as e:
            print(f"⚠️ Could not generate confusion matrix: {e}")
    
    def create_metrics_comparison_bars(self, metrics, output_dir, timestamp):
        """Create metrics comparison bar charts"""
        try:
            methods = list(metrics.keys())
            metric_names = ['precision', 'recall', 'f1', 'accuracy']
            
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Metrics Comparison Across Methods - Universal Evaluation', 
                         fontsize=20, fontweight='bold', color='#2c3e50', y=0.95)
            
            colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c']
            
            for idx, metric in enumerate(metric_names):
                row = idx // 2
                col = idx % 2
                ax = axes[row, col]
                
                values = [metrics[method][metric] for method in methods]
                
                bars = ax.bar(methods, values, color=colors[:len(methods)], 
                             alpha=0.8, edgecolor='white', linewidth=2)
                
                ax.set_title(f'{metric.upper()} Score', fontsize=14, fontweight='bold', color='#2c3e50')
                ax.set_ylabel('Score', fontsize=12, fontweight='bold')
                ax.set_ylim(0, 1.1)
                ax.grid(True, alpha=0.3, axis='y')
                
                for bar, value in zip(bars, values):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                           f'{value:.3f}', ha='center', va='bottom', fontweight='bold', fontsize=11)
                
                ax.tick_params(axis='x', rotation=45)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'metrics_comparison_{timestamp}.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated metrics comparison bars")
        except Exception as e:
            print(f"⚠️ Could not generate metrics comparison: {e}")
    
    def create_performance_summary_table(self, metrics, output_dir, timestamp):
        """Create performance summary table"""
        try:
            methods = list(metrics.keys())
            
            fig, ax = plt.subplots(figsize=(14, 8))
            ax.axis('tight')
            ax.axis('off')
            
            table_data = []
            for method in methods:
                row = [
                    method,
                    f"{metrics[method]['precision']:.3f}",
                    f"{metrics[method]['recall']:.3f}",
                    f"{metrics[method]['f1']:.3f}",
                    f"{metrics[method]['accuracy']:.3f}",
                    f"{metrics[method]['true_positives']}",
                    f"{metrics[method]['false_negatives']}",
                    f"{metrics[method]['avg_detection_time']*1000:.2f}ms"
                ]
                table_data.append(row)
            
            table = ax.table(cellText=table_data,
                           colLabels=['Method', 'Precision', 'Recall', 'F1', 'Accuracy', 
                                     'True Positives', 'False Negatives', 'Avg Time'],
                           cellLoc='center',
                           loc='center',
                           colWidths=[0.15, 0.1, 0.1, 0.1, 0.1, 0.12, 0.12, 0.12])
            
            table.auto_set_font_size(False)
            table.set_fontsize(11)
            table.scale(1.2, 1.5)
            
            for i in range(len(table_data[0])):
                table[(0, i)].set_facecolor('#34495e')
                table[(0, i)].set_text_props(weight='bold', color='white')
            
            for i in range(1, len(table_data) + 1):
                for j in range(len(table_data[0])):
                    if i % 2 == 0:
                        table[(i, j)].set_facecolor('#ecf0f1')
                    else:
                        table[(i, j)].set_facecolor('#ffffff')
            
            plt.title('Universal Evaluation - Complete Performance Summary', 
                      fontsize=18, fontweight='bold', color='#2c3e50', pad=30)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'performance_summary_{timestamp}.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated performance summary table")
        except Exception as e:
            print(f"⚠️ Could not generate performance summary: {e}")
    
    def create_detection_time_comparison(self, metrics, output_dir, timestamp):
        """Create detection time comparison chart"""
        try:
            methods = list(metrics.keys())
            times_ms = [metrics[method]['avg_detection_time'] * 1000 for method in methods]
            
            fig, ax = plt.subplots(figsize=(12, 8))
            
            colors = ['#ff9a9e', '#fecfef', '#fad0c4', '#a8edea']
            bars = ax.barh(methods, times_ms, color=colors[:len(methods)], 
                          alpha=0.8, edgecolor='white', linewidth=2)
            
            ax.set_title('Detection Time Comparison - Universal Evaluation', 
                         fontsize=18, fontweight='bold', color='#2c3e50', pad=20)
            ax.set_xlabel('Average Detection Time (milliseconds)', fontsize=13, fontweight='bold')
            ax.grid(True, alpha=0.3, axis='x')
            
            for bar, time_val in zip(bars, times_ms):
                width = bar.get_width()
                ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                       f'{time_val:.2f}ms', ha='left', va='center', 
                       fontweight='bold', fontsize=11)
            
            fastest_method = methods[times_ms.index(min(times_ms))]
            slowest_method = methods[times_ms.index(max(times_ms))]
            
            insight_text = f"Fastest: {fastest_method} ({min(times_ms):.2f}ms)\nSlowest: {slowest_method} ({max(times_ms):.2f}ms)"
            props = dict(boxstyle='round', facecolor='lightblue', alpha=0.8)
            ax.text(0.02, 0.98, insight_text, transform=ax.transAxes, fontsize=11,
                    verticalalignment='top', bbox=props)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'detection_time_{timestamp}.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated detection time comparison")
        except Exception as e:
            print(f"⚠️ Could not generate detection time chart: {e}")
    
    def create_performance_trends(self, metrics, output_dir, timestamp):
        """Create performance trends line chart"""
        try:
            methods = list(metrics.keys())
            metrics_list = ['precision', 'recall', 'f1', 'accuracy']
            
            fig, ax = plt.subplots(figsize=(12, 8))
            
            colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c']
            
            for i, metric in enumerate(metrics_list):
                values = [metrics[method][metric] for method in methods]
                ax.plot(methods, values, marker='o', linewidth=3, markersize=8,
                       color=colors[i], label=metric.title(), alpha=0.8)
            
            ax.set_title('Performance Trends Across Methods', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            ax.set_xlabel('Detection Methods', fontweight='bold', fontsize=12)
            ax.set_ylabel('Score', fontweight='bold', fontsize=12)
            ax.set_xticklabels(methods, rotation=45, ha='right')
            
            ax.grid(True, alpha=0.3, linestyle='--', color='#bdc3c7')
            ax.set_axisbelow(True)
            ax.set_ylim(0, 1.1)
            
            ax.legend(loc='upper right', framealpha=0.9, fancybox=True, shadow=True)
            
            for method_idx, method in enumerate(methods):
                for metric_idx, metric in enumerate(metrics_list):
                    value = metrics[method][metric]
                    ax.annotate(f'{value:.3f}', 
                               (method_idx, value),
                               textcoords="offset points",
                               xytext=(0, 10),
                               ha='center',
                               fontsize=9,
                               fontweight='bold')
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'performance_trends_{timestamp}.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated performance trends chart")
        except Exception as e:
            print(f"⚠️ Could not generate performance trends: {e}")
    
    def print_evaluation_summary(self, metrics):
        """Print evaluation summary"""
        print(f"\n📊 UNIVERSAL EVALUATION SUMMARY")
        print("=" * 60)
        
        for method, metric in metrics.items():
            print(f"\n{method}:")
            print(f"  • Precision: {metric['precision']:.3f}")
            print(f"  • Recall: {metric['recall']:.3f}")
            print(f"  • F1: {metric['f1']:.3f}")
            print(f"  • Accuracy: {metric['accuracy']:.3f}")
            print(f"  • True Positives: {metric['true_positives']}")
            print(f"  • False Negatives: {metric['false_negatives']}")

def main():
    parser = argparse.ArgumentParser(description='Universal Evaluation System with Automatic Image Generation')
    parser.add_argument('--dataset', '-d', type=str, required=True, help='Dataset path (JSON or CSV)')
    parser.add_argument('--output', '-o', type=str, default='universal_results', help='Output directory')
    args = parser.parse_args()
    
    # Create universal evaluator
    evaluator = UniversalEvaluator()
    
    # Run evaluation
    evaluator.run_evaluation(args.dataset, args.output)

if __name__ == '__main__':
    main()
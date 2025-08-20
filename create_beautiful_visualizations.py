#!/usr/bin/env python3
"""
Create Beautiful Visualizations from CSV Evaluation Results
Generates stunning charts and graphs for the 4k dataset evaluation
"""

import os
import sys
import csv
import json
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd

# Beautiful color schemes
COLORS = {
    'primary': ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'],
    'gradient': ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe'],
    'warm': ['#ff9a9e', '#fecfef', '#fecfef', '#fad0c4', '#ffd1ff', '#a8edea'],
    'cool': ['#a8edea', '#fed6e3', '#ffecd2', '#fcb69f', '#ff9a9e', '#fecfef']
}

def setup_beautiful_style():
    """Set up beautiful matplotlib and seaborn styling"""
    plt.style.use('default')
    
    # Configure seaborn for beautiful plots
    sns.set_palette("husl")
    sns.set_style("whitegrid", {
        'axes.facecolor': '#f8f9fa',
        'axes.edgecolor': '#dee2e6',
        'grid.color': '#e9ecef',
        'grid.linestyle': '--',
        'grid.alpha': 0.7
    })
    
    # Set font properties for better readability
    plt.rcParams['font.size'] = 11
    plt.rcParams['axes.titlesize'] = 16
    plt.rcParams['axes.labelsize'] = 13
    plt.rcParams['xtick.labelsize'] = 11
    plt.rcParams['ytick.labelsize'] = 11
    plt.rcParams['legend.fontsize'] = 11
    plt.rcParams['figure.titlesize'] = 18

def load_metrics_from_csv(csv_file):
    """Load metrics data from CSV file"""
    metrics = {}
    confusion_matrix_data = {}
    
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        rows = list(reader)
        
        # Find the metrics section
        metric_start = 0
        for i, row in enumerate(rows):
            if row and row[0] == 'Metric':
                metric_start = i
                break
        
        # Extract metrics
        if metric_start >= 0:
            headers = rows[metric_start]
            for i in range(metric_start + 1, len(rows)):
                if not rows[i] or rows[i][0] == '' or rows[i][0].startswith('Confusion'):
                    break
                metric_name = rows[i][0]
                metrics[metric_name] = {}
                for j, method in enumerate(headers[1:], 1):
                    try:
                        value = float(rows[i][j])
                        metrics[metric_name][method] = value
                    except (ValueError, IndexError):
                        metrics[metric_name][method] = 0
        
        # Find confusion matrix section
        cm_start = 0
        for i, row in enumerate(rows):
            if row and row[0] == 'Confusion Matrix Data':
                cm_start = i
                break
        
        # Extract confusion matrix data
        if cm_start > 0:
            for i in range(cm_start + 2, len(rows)):
                if not rows[i] or len(rows[i]) < 5:
                    break
                method = rows[i][0]
                confusion_matrix_data[method] = {
                    'tp': int(rows[i][1]),
                    'tn': int(rows[i][2]),
                    'fp': int(rows[i][3]),
                    'fn': int(rows[i][4])
                }
    
    return metrics, confusion_matrix_data

def create_performance_radar_chart(metrics, output_dir):
    """Create a beautiful radar chart for performance metrics"""
    fig, ax = plt.subplots(figsize=(12, 10), subplot_kw=dict(projection='polar'))
    
    # Metrics to show on radar chart
    radar_metrics = ['precision', 'recall', 'f1', 'accuracy']
    methods = list(metrics['precision'].keys())
    
    # Calculate angles for each metric
    angles = np.linspace(0, 2 * np.pi, len(radar_metrics), endpoint=False).tolist()
    angles += angles[:1]  # Complete the circle
    
    # Plot each method
    for i, method in enumerate(methods):
        values = [metrics[metric][method] for metric in radar_metrics]
        values += values[:1]  # Complete the circle
        
        ax.plot(angles, values, 'o-', linewidth=3, markersize=8, 
               label=method, color=COLORS['primary'][i % len(COLORS['primary'])], alpha=0.8)
        ax.fill(angles, values, alpha=0.1, color=COLORS['primary'][i % len(COLORS['primary'])])
    
    # Customize the plot
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels([metric.upper() for metric in radar_metrics], fontsize=12, fontweight='bold')
    ax.set_ylim(0, 1.1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=10)
    ax.grid(True, alpha=0.3)
    
    # Add legend
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=12)
    
    # Add title
    plt.title('Performance Radar Chart - 4K Dataset Evaluation', 
              fontsize=18, fontweight='bold', pad=30, color='#2c3e50')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'performance_radar_chart.png'), 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Generated performance radar chart")

def create_confusion_matrix_heatmap(confusion_matrix_data, output_dir):
    """Create beautiful confusion matrix heatmaps for each method"""
    methods = list(confusion_matrix_data.keys())
    
    # Create subplot grid
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Confusion Matrix Heatmaps - 4K Dataset Evaluation', 
                 fontsize=20, fontweight='bold', color='#2c3e50', y=0.95)
    
    for idx, method in enumerate(methods):
        row = idx // 2
        col = idx % 2
        ax = axes[row, col]
        
        # Create confusion matrix
        cm_data = confusion_matrix_data[method]
        cm = np.array([[cm_data['tn'], cm_data['fp']], 
                      [cm_data['fn'], cm_data['tp']]])
        
        # Create heatmap
        sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlBu_r', 
                   xticklabels=['Benign', 'Adversarial'],
                   yticklabels=['Benign', 'Adversarial'],
                   ax=ax, cbar_kws={'shrink': 0.8})
        
        # Customize
        ax.set_title(f'{method}', fontsize=14, fontweight='bold', color='#2c3e50')
        ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
        ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
        
        # Add metrics text
        total = cm_data['tp'] + cm_data['tn'] + cm_data['fp'] + cm_data['fn']
        accuracy = (cm_data['tp'] + cm_data['tn']) / total
        precision = cm_data['tp'] / (cm_data['tp'] + cm_data['fp']) if (cm_data['tp'] + cm_data['fp']) > 0 else 0
        recall = cm_data['tp'] / (cm_data['tp'] + cm_data['fn']) if (cm_data['tp'] + cm_data['fn']) > 0 else 0
        
        textstr = f'Accuracy: {accuracy:.3f}\nPrecision: {precision:.3f}\nRecall: {recall:.3f}'
        props = dict(boxstyle='round', facecolor='wheat', alpha=0.8)
        ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=10,
                verticalalignment='top', bbox=props)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'confusion_matrix_heatmaps.png'), 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Generated confusion matrix heatmaps")

def create_metrics_comparison_bar_chart(metrics, output_dir):
    """Create beautiful bar charts comparing metrics across methods"""
    methods = list(metrics['precision'].keys())
    metric_names = ['precision', 'recall', 'f1', 'accuracy']
    
    # Create subplot grid
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Metrics Comparison Across Methods - 4K Dataset', 
                 fontsize=20, fontweight='bold', color='#2c3e50', y=0.95)
    
    for idx, metric in enumerate(metric_names):
        row = idx // 2
        col = idx % 2
        ax = axes[row, col]
        
        # Get values for this metric
        values = [metrics[metric][method] for method in methods]
        
        # Create beautiful bar chart
        bars = ax.bar(methods, values, color=COLORS['gradient'][:len(methods)], 
                     alpha=0.8, edgecolor='white', linewidth=2)
        
        # Customize
        ax.set_title(f'{metric.upper()} Score', fontsize=14, fontweight='bold', color='#2c3e50')
        ax.set_ylabel('Score', fontsize=12, fontweight='bold')
        ax.set_ylim(0, 1.1)
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                   f'{value:.3f}', ha='center', va='bottom', fontweight='bold', fontsize=11)
        
        # Rotate x-axis labels for better readability
        ax.tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'metrics_comparison_bars.png'), 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Generated metrics comparison bar charts")

def create_performance_summary_table(metrics, confusion_matrix_data, output_dir):
    """Create a beautiful summary table visualization"""
    methods = list(metrics['precision'].keys())
    
    # Create figure with table
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare table data
    table_data = []
    for method in methods:
        row = [
            method,
            f"{metrics['precision'][method]:.3f}",
            f"{metrics['recall'][method]:.3f}",
            f"{metrics['f1'][method]:.3f}",
            f"{metrics['accuracy'][method]:.3f}",
            f"{confusion_matrix_data[method]['tp']}",
            f"{confusion_matrix_data[method]['fn']}",
            f"{metrics['avg_detection_time'][method]*1000:.2f}ms"
        ]
        table_data.append(row)
    
    # Create table
    table = ax.table(cellText=table_data,
                    colLabels=['Method', 'Precision', 'Recall', 'F1', 'Accuracy', 
                              'True Positives', 'False Negatives', 'Avg Time'],
                    cellLoc='center',
                    loc='center',
                    colWidths=[0.15, 0.1, 0.1, 0.1, 0.1, 0.12, 0.12, 0.12])
    
    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.2, 1.5)
    
    # Color header row
    for i in range(len(table_data[0])):
        table[(0, i)].set_facecolor('#34495e')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # Color alternating rows
    for i in range(1, len(table_data) + 1):
        for j in range(len(table_data[0])):
            if i % 2 == 0:
                table[(i, j)].set_facecolor('#ecf0f1')
            else:
                table[(i, j)].set_facecolor('#ffffff')
    
    # Add title
    plt.title('4K Dataset Evaluation - Complete Performance Summary', 
              fontsize=18, fontweight='bold', color='#2c3e50', pad=30)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'performance_summary_table.png'), 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Generated performance summary table")

def create_detection_time_comparison(metrics, output_dir):
    """Create beautiful detection time comparison chart"""
    methods = list(metrics['avg_detection_time'].keys())
    times_ms = [metrics['avg_detection_time'][method] * 1000 for method in methods]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Create horizontal bar chart for better readability
    bars = ax.barh(methods, times_ms, color=COLORS['warm'][:len(methods)], 
                   alpha=0.8, edgecolor='white', linewidth=2)
    
    # Customize
    ax.set_title('Detection Time Comparison - 4K Dataset', 
                 fontsize=18, fontweight='bold', color='#2c3e50', pad=20)
    ax.set_xlabel('Average Detection Time (milliseconds)', fontsize=13, fontweight='bold')
    ax.grid(True, alpha=0.3, axis='x')
    
    # Add value labels on bars
    for bar, time_val in zip(bars, times_ms):
        width = bar.get_width()
        ax.text(width + 0.1, bar.get_y() + bar.get_height()/2,
               f'{time_val:.2f}ms', ha='left', va='center', 
               fontweight='bold', fontsize=11)
    
    # Add performance insights
    fastest_method = methods[times_ms.index(min(times_ms))]
    slowest_method = methods[times_ms.index(max(times_ms))]
    
    insight_text = f"Fastest: {fastest_method} ({min(times_ms):.2f}ms)\nSlowest: {slowest_method} ({max(times_ms):.2f}ms)"
    props = dict(boxstyle='round', facecolor='lightblue', alpha=0.8)
    ax.text(0.02, 0.98, insight_text, transform=ax.transAxes, fontsize=11,
            verticalalignment='top', bbox=props)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'detection_time_comparison.png'), 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Generated detection time comparison chart")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 create_beautiful_visualizations.py <metrics_csv> <output_dir>")
        print("Example: python3 create_beautiful_visualizations.py results_csv_evaluation/metrics_20250820_004034.csv beautiful_viz")
        sys.exit(1)
    
    metrics_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.exists(metrics_file):
        print(f"❌ Metrics file not found: {metrics_file}")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    print("🎨 Creating Beautiful Visualizations for 4K Dataset Evaluation...")
    print("=" * 70)
    
    # Load data
    print("📊 Loading metrics data...")
    metrics, confusion_matrix_data = load_metrics_from_csv(metrics_file)
    
    if not metrics:
        print("❌ No metrics data found in CSV file")
        sys.exit(1)
    
    # Setup beautiful styling
    setup_beautiful_style()
    
    # Create all visualizations
    print("\n🎨 Generating visualizations...")
    
    try:
        create_performance_radar_chart(metrics, output_dir)
        create_confusion_matrix_heatmap(confusion_matrix_data, output_dir)
        create_metrics_comparison_bar_chart(metrics, output_dir)
        create_performance_summary_table(metrics, confusion_matrix_data, output_dir)
        create_detection_time_comparison(metrics, output_dir)
        
        print(f"\n✅ All visualizations created successfully!")
        print(f"📁 Output directory: {output_dir}")
        print(f"🎯 Files generated:")
        print(f"   • performance_radar_chart.png")
        print(f"   • confusion_matrix_heatmaps.png")
        print(f"   • metrics_comparison_bars.png")
        print(f"   • performance_summary_table.png")
        print(f"   • detection_time_comparison.png")
        
    except Exception as e:
        print(f"❌ Error creating visualizations: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
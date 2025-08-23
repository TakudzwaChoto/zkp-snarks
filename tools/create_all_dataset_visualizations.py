#!/usr/bin/env python3
"""
Create comprehensive visualizations for all datasets in the anti-collusion system evaluation.
Generates charts, graphs, and figures for all 5 datasets with performance metrics.
"""

import os
import json
import csv
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import seaborn as sns
from datetime import datetime
import pandas as pd

# Set style for better-looking plots
plt.style.use('default')
sns.set_palette("husl")

# Configuration
RESULTS_DIR = 'results_comprehensive_renamed'
OUTPUT_DIR = 'results_visualizations_complete'
DATASETS = {
    '4k_curated': {'size': 16001, 'type': 'Curated', 'color': '#1f77b4'},
    '6k_kaggle': {'size': 6499, 'type': 'Kaggle', 'color': '#ff7f0e'},
    '50k_curated': {'size': 200001, 'type': 'Curated', 'color': '#2ca02c'},
    '200k_curated': {'size': 800001, 'type': 'Curated', 'color': '#d62728'},
    '120k_kaggle': {'size': 39220, 'type': 'Kaggle', 'color': '#9467bd'}
}

def load_dataset_results():
    """Load all dataset evaluation results."""
    results = {}
    
    for dataset_name in DATASETS.keys():
        # Look for the most recent evaluation file
        pattern = f"{dataset_name}_evaluation_*.json"
        files = [f for f in os.listdir(RESULTS_DIR) if f.startswith(f"{dataset_name}_evaluation_")]
        
        if files:
            # Get the most recent file
            latest_file = sorted(files)[-1]
            file_path = os.path.join(RESULTS_DIR, latest_file)
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    results[dataset_name] = data
                    print(f"✓ Loaded {dataset_name}: {data}")
            except Exception as e:
                print(f"✗ Error loading {dataset_name}: {e}")
        else:
            print(f"✗ No results found for {dataset_name}")
    
    return results

def create_output_directory():
    """Create output directory for visualizations."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"✓ Created output directory: {OUTPUT_DIR}")

def create_performance_comparison_chart(results):
    """Create comprehensive performance comparison chart."""
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Anti-Collusion System Performance Across All Datasets', fontsize=16, fontweight='bold')
    
    # Extract data
    datasets = list(results.keys())
    detection_rates = [results[d]['collusion_detection_rate'] * 100 for d in datasets]
    false_positive_rates = [results[d]['false_positive_rate'] * 100 for d in datasets]
    tamper_resistance = [results[d]['tamper_resistance'] * 100 for d in datasets]
    throughput = [results[d]['throughput_rpm'] for d in datasets]
    
    # 1. Detection Rate Comparison
    bars1 = ax1.bar(datasets, detection_rates, color=[DATASETS[d]['color'] for d in datasets], alpha=0.8)
    ax1.set_title('Detection Rate Comparison', fontweight='bold')
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_ylim(0, 110)
    ax1.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for bar, value in zip(bars1, detection_rates):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')
    
    # 2. False Positive Rate Comparison
    bars2 = ax2.bar(datasets, false_positive_rates, color=[DATASETS[d]['color'] for d in datasets], alpha=0.8)
    ax2.set_title('False Positive Rate Comparison', fontweight='bold')
    ax2.set_ylabel('False Positive Rate (%)')
    ax2.set_ylim(0, 5)
    ax2.grid(True, alpha=0.3)
    
    for bar, value in zip(bars2, false_positive_rates):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{value:.2f}%', ha='center', va='bottom', fontweight='bold')
    
    # 3. Tamper Resistance Comparison
    bars3 = ax3.bar(datasets, tamper_resistance, color=[DATASETS[d]['color'] for d in datasets], alpha=0.8)
    ax3.set_title('Tamper Resistance Comparison', fontweight='bold')
    ax3.set_ylabel('Tamper Resistance (%)')
    ax3.set_ylim(0, 110)
    ax3.grid(True, alpha=0.3)
    
    for bar, value in zip(bars3, tamper_resistance):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')
    
    # 4. Throughput Comparison
    bars4 = ax4.bar(datasets, throughput, color=[DATASETS[d]['color'] for d in datasets], alpha=0.8)
    ax4.set_title('Throughput Comparison', fontweight='bold')
    ax4.set_ylabel('Throughput (RPM)')
    ax4.grid(True, alpha=0.3)
    
    for bar, value in zip(bars4, throughput):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 20,
                f'{value:.0f}', ha='center', va='bottom', fontweight='bold')
    
    # Rotate x-axis labels for better readability
    for ax in [ax1, ax2, ax3, ax4]:
        ax.tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'all_datasets_performance_comparison.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Created all datasets performance comparison chart")

def create_scalability_analysis_chart(results):
    """Create scalability analysis chart showing performance vs dataset size."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Anti-Collusion System Scalability Analysis', fontsize=16, fontweight='bold')
    
    # Extract data
    sizes = [DATASETS[d]['size'] for d in results.keys()]
    detection_rates = [results[d]['collusion_detection_rate'] * 100 for d in results.keys()]
    throughput = [results[d]['throughput_rpm'] for d in results.keys()]
    latency = [results[d]['latency_ms'] for d in results.keys()]
    
    # Sort by size for better visualization
    sorted_indices = np.argsort(sizes)
    sizes = [sizes[i] for i in sorted_indices]
    detection_rates = [detection_rates[i] for i in sorted_indices]
    throughput = [throughput[i] for i in sorted_indices]
    latency = [latency[i] for i in sorted_indices]
    
    # 1. Detection Rate vs Dataset Size
    ax1.semilogx(sizes, detection_rates, 'o-', linewidth=3, markersize=8, 
                 color='#2ca02c', markerfacecolor='white', markeredgewidth=2)
    ax1.set_title('Detection Rate vs Dataset Size', fontweight='bold')
    ax1.set_xlabel('Dataset Size (entries)')
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_ylim(95, 105)
    ax1.grid(True, alpha=0.3)
    ax1.set_xticks([10000, 100000, 1000000])
    ax1.set_xticklabels(['10K', '100K', '1M'])
    
    # Add value labels
    for i, (size, rate) in enumerate(zip(sizes, detection_rates)):
        ax1.annotate(f'{rate:.1f}%', (size, rate), 
                    xytext=(10, 10), textcoords='offset points',
                    fontweight='bold', ha='center')
    
    # 2. Throughput vs Dataset Size
    ax2.semilogx(sizes, throughput, 's-', linewidth=3, markersize=8,
                 color='#1f77b4', markerfacecolor='white', markeredgewidth=2)
    ax2.set_title('Throughput vs Dataset Size', fontweight='bold')
    ax2.set_xlabel('Dataset Size (entries)')
    ax2.set_ylabel('Throughput (RPM)')
    ax2.set_ylim(6600, 6630)
    ax2.grid(True, alpha=0.3)
    ax2.set_xticks([10000, 100000, 1000000])
    ax2.set_xticklabels(['10K', '100K', '1M'])
    
    # Add value labels
    for i, (size, tput) in enumerate(zip(sizes, throughput)):
        ax2.annotate(f'{tput:.0f}', (size, tput), 
                    xytext=(10, 10), textcoords='offset points',
                    fontweight='bold', ha='center')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'scalability_analysis.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Created scalability analysis chart")

def create_dataset_type_comparison_chart(results):
    """Create comparison chart between curated and Kaggle datasets."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Dataset Type Performance Comparison', fontsize=16, fontweight='bold')
    
    # Separate datasets by type
    curated_datasets = [d for d in results.keys() if DATASETS[d]['type'] == 'Curated']
    kaggle_datasets = [d for d in results.keys() if DATASETS[d]['type'] == 'Kaggle']
    
    # Calculate averages for each type
    curated_avg = {
        'detection_rate': np.mean([results[d]['collusion_detection_rate'] * 100 for d in curated_datasets]),
        'false_positive_rate': np.mean([results[d]['false_positive_rate'] * 100 for d in curated_datasets]),
        'throughput': np.mean([results[d]['throughput_rpm'] for d in curated_datasets])
    }
    
    kaggle_avg = {
        'detection_rate': np.mean([results[d]['collusion_detection_rate'] * 100 for d in kaggle_datasets]),
        'false_positive_rate': np.mean([results[d]['false_positive_rate'] * 100 for d in kaggle_datasets]),
        'throughput': np.mean([results[d]['throughput_rpm'] for d in kaggle_datasets])
    }
    
    # 1. Detection Rate by Type
    types = ['Curated', 'Kaggle']
    detection_rates = [curated_avg['detection_rate'], kaggle_avg['detection_rate']]
    colors = ['#2ca02c', '#ff7f0e']
    
    bars1 = ax1.bar(types, detection_rates, color=colors, alpha=0.8)
    ax1.set_title('Average Detection Rate by Dataset Type', fontweight='bold')
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_ylim(0, 110)
    ax1.grid(True, alpha=0.3)
    
    for bar, value in zip(bars1, detection_rates):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')
    
    # 2. Throughput by Type
    throughput_values = [curated_avg['throughput'], kaggle_avg['throughput']]
    bars2 = ax2.bar(types, throughput_values, color=colors, alpha=0.8)
    ax2.set_title('Average Throughput by Dataset Type', fontweight='bold')
    ax2.set_ylabel('Throughput (RPM)')
    ax2.grid(True, alpha=0.3)
    
    for bar, value in zip(bars2, throughput_values):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 20,
                f'{value:.0f}', ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'dataset_type_comparison.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Created dataset type comparison chart")

def create_performance_heatmap(results):
    """Create performance metrics heatmap."""
    # Prepare data for heatmap
    metrics = ['collusion_detection_rate', 'false_positive_rate', 'tamper_resistance', 'throughput_rpm', 'latency_ms']
    metric_labels = ['Detection Rate', 'False Positive Rate', 'Tamper Resistance', 'Throughput', 'Latency']
    
    # Normalize data for better visualization
    heatmap_data = []
    for metric in metrics:
        row = []
        for dataset in results.keys():
            value = results[dataset][metric]
            if metric in ['collusion_detection_rate', 'tamper_resistance']:
                # Convert to percentage and normalize to 0-1
                row.append(value)
            elif metric == 'false_positive_rate':
                # Keep as is (already 0-1)
                row.append(value)
            elif metric == 'throughput_rpm':
                # Normalize throughput (min-max scaling)
                row.append((value - 6600) / (6630 - 6600))
            elif metric == 'latency_ms':
                # Normalize latency (inverse, so lower is better)
                row.append(1 - (value - 15.0) / (15.3 - 15.0))
        heatmap_data.append(row)
    
    # Create heatmap
    plt.figure(figsize=(12, 8))
    sns.heatmap(heatmap_data, 
                xticklabels=list(results.keys()),
                yticklabels=metric_labels,
                annot=True, 
                fmt='.3f',
                cmap='RdYlGn_r',
                cbar_kws={'label': 'Normalized Performance Score'})
    
    plt.title('Performance Metrics Heatmap Across All Datasets', fontsize=16, fontweight='bold')
    plt.xlabel('Datasets')
    plt.ylabel('Performance Metrics')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    plt.savefig(os.path.join(OUTPUT_DIR, 'performance_heatmap.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Created performance heatmap")

def create_summary_statistics_chart(results):
    """Create summary statistics chart."""
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Anti-Collusion System Summary Statistics', fontsize=16, fontweight='bold')
    
    # Extract all values for statistical analysis
    all_detection_rates = [results[d]['collusion_detection_rate'] * 100 for d in results.keys()]
    all_false_positive_rates = [results[d]['false_positive_rate'] * 100 for d in results.keys()]
    all_throughput = [results[d]['throughput_rpm'] for d in results.keys()]
    all_latency = [results[d]['latency_ms'] for d in results.keys()]
    
    # 1. Detection Rate Distribution
    ax1.hist(all_detection_rates, bins=5, color='#2ca02c', alpha=0.7, edgecolor='black')
    ax1.set_title('Detection Rate Distribution', fontweight='bold')
    ax1.set_xlabel('Detection Rate (%)')
    ax1.set_ylabel('Frequency')
    ax1.axvline(np.mean(all_detection_rates), color='red', linestyle='--', 
                label=f'Mean: {np.mean(all_detection_rates):.1f}%')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. False Positive Rate Distribution
    ax2.hist(all_false_positive_rates, bins=5, color='#d62728', alpha=0.7, edgecolor='black')
    ax2.set_title('False Positive Rate Distribution', fontweight='bold')
    ax2.set_xlabel('False Positive Rate (%)')
    ax2.set_ylabel('Frequency')
    ax2.axvline(np.mean(all_false_positive_rates), color='red', linestyle='--',
                label=f'Mean: {np.mean(all_false_positive_rates):.2f}%')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # 3. Throughput Distribution
    ax3.hist(all_throughput, bins=5, color='#1f77b4', alpha=0.7, edgecolor='black')
    ax3.set_title('Throughput Distribution', fontweight='bold')
    ax3.set_xlabel('Throughput (RPM)')
    ax3.set_ylabel('Frequency')
    ax3.axvline(np.mean(all_throughput), color='red', linestyle='--',
                label=f'Mean: {np.mean(all_throughput):.0f} RPM')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # 4. Latency Distribution
    ax4.hist(all_latency, bins=5, color='#ff7f0e', alpha=0.7, edgecolor='black')
    ax4.set_title('Latency Distribution', fontweight='bold')
    ax4.set_xlabel('Latency (ms)')
    ax4.set_ylabel('Frequency')
    ax4.axvline(np.mean(all_latency), color='red', linestyle='--',
                label=f'Mean: {np.mean(all_latency):.2f} ms')
    ax4.legend()
    ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'summary_statistics.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Created summary statistics chart")

def create_comprehensive_dashboard(results):
    """Create a comprehensive dashboard combining all visualizations."""
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle('Anti-Collusion System Comprehensive Performance Dashboard', 
                 fontsize=20, fontweight='bold', y=0.98)
    
    # Create grid layout
    gs = fig.add_gridspec(4, 4, hspace=0.3, wspace=0.3)
    
    # 1. Performance Overview (top left, spans 2x2)
    ax1 = fig.add_subplot(gs[0:2, 0:2])
    datasets = list(results.keys())
    detection_rates = [results[d]['collusion_detection_rate'] * 100 for d in datasets]
    colors = [DATASETS[d]['color'] for d in datasets]
    
    bars = ax1.bar(datasets, detection_rates, color=colors, alpha=0.8)
    ax1.set_title('Detection Rate Across All Datasets', fontweight='bold', fontsize=14)
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_ylim(0, 110)
    ax1.grid(True, alpha=0.3)
    ax1.tick_params(axis='x', rotation=45)
    
    for bar, value in zip(bars, detection_rates):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')
    
    # 2. Scalability Analysis (top right, spans 2x2)
    ax2 = fig.add_subplot(gs[0:2, 2:4])
    sizes = [DATASETS[d]['size'] for d in datasets]
    throughput = [results[d]['throughput_rpm'] for d in datasets]
    
    ax2.semilogx(sizes, throughput, 'o-', linewidth=3, markersize=10, 
                 color='#2ca02c', markerfacecolor='white', markeredgewidth=2)
    ax2.set_title('Throughput vs Dataset Size', fontweight='bold', fontsize=14)
    ax2.set_xlabel('Dataset Size (entries)')
    ax2.set_ylabel('Throughput (RPM)')
    ax2.set_ylim(6600, 6630)
    ax2.grid(True, alpha=0.3)
    ax2.set_xticks([10000, 100000, 1000000])
    ax2.set_xticklabels(['10K', '100K', '1M'])
    
    # 3. Performance Metrics (bottom left, spans 2x2)
    ax3 = fig.add_subplot(gs[2:4, 0:2])
    metrics = ['Detection Rate', 'False Positive Rate', 'Tamper Resistance']
    curated_avg = [
        np.mean([results[d]['collusion_detection_rate'] * 100 for d in datasets if DATASETS[d]['type'] == 'Curated']),
        np.mean([results[d]['false_positive_rate'] * 100 for d in datasets if DATASETS[d]['type'] == 'Curated']),
        np.mean([results[d]['tamper_resistance'] * 100 for d in datasets if DATASETS[d]['type'] == 'Curated'])
    ]
    kaggle_avg = [
        np.mean([results[d]['collusion_detection_rate'] * 100 for d in datasets if DATASETS[d]['type'] == 'Kaggle']),
        np.mean([results[d]['false_positive_rate'] * 100 for d in datasets if DATASETS[d]['type'] == 'Curated']),
        np.mean([results[d]['tamper_resistance'] * 100 for d in datasets if DATASETS[d]['type'] == 'Kaggle'])
    ]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    bars1 = ax3.bar(x - width/2, curated_avg, width, label='Curated Datasets', color='#2ca02c', alpha=0.8)
    bars2 = ax3.bar(x + width/2, kaggle_avg, width, label='Kaggle Datasets', color='#ff7f0e', alpha=0.8)
    
    ax3.set_title('Performance by Dataset Type', fontweight='bold', fontsize=14)
    ax3.set_ylabel('Performance (%)')
    ax3.set_xticks(x)
    ax3.set_xticklabels(metrics)
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # 4. Summary Statistics (bottom right, spans 2x2)
    ax4 = fig.add_subplot(gs[2:4, 2:4])
    
    # Create summary table
    summary_data = [
        ['Total Datasets', f'{len(datasets)}'],
        ['Total Entries', f'{sum([DATASETS[d]["size"] for d in datasets]):,}'],
        ['Avg Detection Rate', f'{np.mean(detection_rates):.1f}%'],
        ['Avg False Positive Rate', f'{np.mean([results[d]["false_positive_rate"] * 100 for d in datasets]):.2f}%'],
        ['Avg Throughput', f'{np.mean(throughput):.0f} RPM'],
        ['Avg Latency', f'{np.mean([results[d]["latency_ms"] for d in datasets]):.2f} ms']
    ]
    
    table = ax4.table(cellText=summary_data, 
                     colLabels=['Metric', 'Value'],
                     cellLoc='center',
                     loc='center',
                     bbox=[0, 0, 1, 1])
    table.auto_set_font_size(False)
    table.set_fontsize(12)
    table.scale(1, 2)
    
    # Style the table
    for i in range(len(summary_data) + 1):
        for j in range(2):
            if i == 0:  # Header row
                table[(i, j)].set_facecolor('#4CAF50')
                table[(i, j)].set_text_props(weight='bold', color='white')
            else:
                table[(i, j)].set_facecolor('#f0f0f0' if i % 2 == 0 else 'white')
    
    ax4.set_title('System Summary', fontweight='bold', fontsize=14)
    ax4.axis('off')
    
    plt.savefig(os.path.join(OUTPUT_DIR, 'comprehensive_dashboard.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Created comprehensive dashboard")

def main():
    """Main function to create all visualizations."""
    print("=== Creating Comprehensive Dataset Visualizations ===")
    print(f"Results directory: {RESULTS_DIR}")
    print(f"Output directory: {OUTPUT_DIR}")
    
    # Create output directory
    create_output_directory()
    
    # Load results
    print("\n--- Loading Dataset Results ---")
    results = load_dataset_results()
    
    if not results:
        print("✗ No results found. Please run evaluation first.")
        return
    
    print(f"✓ Loaded {len(results)} dataset results")
    
    # Create all visualizations
    print("\n--- Creating Visualizations ---")
    
    try:
        create_performance_comparison_chart(results)
        create_scalability_analysis_chart(results)
        create_dataset_type_comparison_chart(results)
        create_performance_heatmap(results)
        create_summary_statistics_chart(results)
        create_comprehensive_dashboard(results)
        
        print(f"\n✅ All visualizations created successfully!")
        print(f"📁 Output directory: {OUTPUT_DIR}")
        print(f"📊 Total visualizations: 6 comprehensive charts")
        
        # List generated files
        files = os.listdir(OUTPUT_DIR)
        print(f"\n📋 Generated files:")
        for file in sorted(files):
            if file.endswith('.png'):
                file_path = os.path.join(OUTPUT_DIR, file)
                file_size = os.path.getsize(file_path) / 1024  # KB
                print(f"  • {file} ({file_size:.1f} KB)")
        
    except Exception as e:
        print(f"✗ Error creating visualizations: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
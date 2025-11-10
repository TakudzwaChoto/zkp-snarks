"""
Create curved line graphs for Security Analysis Metrics
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from scipy import interpolate
import re

# Security Analysis Metrics Data
security_data = {
    '4k': {
        'NON-STRICT ASR': 0.0475,
        'STRICT ASR': 0.0000,
        'Top Category ASR': 0.1772,
        'L2 Blocking': 90.3,
        'L5 Blocking': 5.7,
        'L3 Blocking': 4.0
    },
    '6k': {
        'NON-STRICT ASR': 0.0477,
        'STRICT ASR': 0.0000,
        'Top Category ASR': 0.1759,
        'L2 Blocking': 89.5,
        'L5 Blocking': 5.6,
        'L3 Blocking': 4.8
    },
    '50k': {
        'NON-STRICT ASR': 0.0495,
        'STRICT ASR': 0.0000,
        'Top Category ASR': 0.1806,
        'L2 Blocking': 89.4,
        'L5 Blocking': 6.0,
        'L3 Blocking': 4.5
    },
    '120k': {
        'NON-STRICT ASR': 0.0483,
        'STRICT ASR': 0.0000,
        'Top Category ASR': 0.1763,
        'L2 Blocking': 89.8,
        'L5 Blocking': 5.8,
        'L3 Blocking': 4.4
    },
    '200k': {
        'NON-STRICT ASR': 0.0485,
        'STRICT ASR': 0.0000,
        'Top Category ASR': 0.1774,
        'L2 Blocking': 89.7,
        'L5 Blocking': 5.8,
        'L3 Blocking': 4.4
    }
}

datasets = ['4k', '6k', '50k', '120k', '200k']

# Distinct colors for each metric
metric_colors = {
    'NON-STRICT ASR': '#FF6B6B',      # Red
    'STRICT ASR': '#4ECDC4',          # Teal
    'Top Category ASR': '#45B7D1',    # Blue
    'L2 Blocking': '#96CEB4',         # Green
    'L5 Blocking': '#FFA500',         # Orange
    'L3 Blocking': '#FF00FF'          # Magenta
}

# Line styles for additional distinction
metric_line_styles = {
    'NON-STRICT ASR': '-',      # Solid
    'STRICT ASR': '--',         # Dashed
    'Top Category ASR': '-.',   # Dash-dot
    'L2 Blocking': ':',         # Dotted
    'L5 Blocking': (0, (3, 1, 1, 1)),  # Custom
    'L3 Blocking': (0, (1, 1))         # Dotted
}

# Marker styles
metric_markers = {
    'NON-STRICT ASR': 'o',  # Circle
    'STRICT ASR': 's',      # Square
    'Top Category ASR': '^', # Triangle up
    'L2 Blocking': 'D',     # Diamond
    'L5 Blocking': 'v',     # Triangle down
    'L3 Blocking': 'X'      # X
}

def create_security_metrics_curved_graph():
    """Create curved line graph for all security metrics"""
    
    plt.figure(figsize=(16, 10))
    
    x_positions = np.arange(len(datasets))
    x_smooth = np.linspace(0, len(datasets)-1, 300)
    
    # Metrics to plot (excluding STRICT ASR since it's always 0)
    metrics_to_plot = ['NON-STRICT ASR', 'Top Category ASR', 'L2 Blocking', 'L5 Blocking', 'L3 Blocking']
    
    # Plot each metric with curved lines
    for metric in metrics_to_plot:
        values = [security_data[dataset][metric] for dataset in datasets]
        
        # Create cubic spline interpolation for smooth curves
        spline = interpolate.CubicSpline(x_positions, values)
        y_smooth = spline(x_smooth)
        
        # Plot the smooth curve
        plt.plot(x_smooth, y_smooth, 
                linewidth=2.5,
                linestyle=metric_line_styles[metric],
                label=metric,
                color=metric_colors[metric],
                alpha=0.9)
        
        # Add markers at original data points
        plt.scatter(x_positions, values, 
                   marker=metric_markers[metric],
                   s=80,
                   color=metric_colors[metric],
                   edgecolor='black',
                   linewidth=1.5,
                   zorder=5)
        
        # Add value annotations for key points
        add_metric_annotations(x_positions, values, metric, metric_colors[metric])
    
    # Add security insights annotations
    add_security_insights()
    
    plt.title('', fontsize=18, fontweight='bold', pad=25)
    plt.ylabel('Metrics Value', fontsize=14, fontweight='bold')
    plt.xlabel('Dataset Size', fontsize=14, fontweight='bold')
    plt.xticks(x_positions, datasets, fontsize=12)
    
    # Set different y-axis scales for different metric types
    plt.ylim(0, 100)
    
    plt.grid(True, alpha=0.2, linestyle='--', linewidth=0.5)
    
    # Enhanced legend
    legend = plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=11,
                       frameon=True, fancybox=True, shadow=True, framealpha=0.95)
    
    plt.tight_layout()
    
    output_path = Path('results/security_metrics_curved_graph.png')
    output_path.parent.mkdir(exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Security metrics curved graph saved to: {output_path}")
    
    plt.show()

def add_metric_annotations(x_positions, values, metric, color):
    """Add value annotations for metrics"""
    
    # Annotate first, middle, and last points to avoid clutter
    indices_to_annotate = [0, len(x_positions)//2, len(x_positions)-1]
    
    for idx in indices_to_annotate:
        x = x_positions[idx]
        y = values[idx]
        
        # Format value based on metric type
        if 'ASR' in metric:
            value_text = f'{y:.4f}'
        else:  # Blocking percentages
            value_text = f'{y:.1f}%'
        
        # Position annotation to avoid overlap
        vertical_offset = 3 if 'Blocking' in metric else 0.005
        text_y = y + vertical_offset if idx != len(x_positions)-1 else y - vertical_offset
        
        plt.annotate(value_text,
                   xy=(x, y),
                   xytext=(x, text_y),
                   textcoords='data',
                   fontsize=9,
                   fontweight='bold',
                   color=color,
                   ha='center',
                   bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.9, edgecolor=color))

def add_security_insights():
    """Add security insights annotations"""
    
    insights = [
        (2, 90, "🎯 L2 Layer: Primary Defense\n(89-90% blocking rate)", '#96CEB4', 
         dict(arrowstyle='->', color='#96CEB4', lw=2.0)),
        (1, 0.18, "⚠️ Instruction Bypass:\nMost Common Attack\n(17.5-18.1% ASR)", '#45B7D1',
         dict(arrowstyle='->', color='#45B7D1', lw=2.0)),
        (3, 0.05, "✅ NON-STRICT ASR:\nConsistently Low\n(4.7-5.0%)", '#FF6B6B',
         dict(arrowstyle='->', color='#FF6B6B', lw=2.0)),
        (0, 6, "🛡️ Multi-Layer Defense:\nL2 + L5 + L3 Coverage", '#FFA500',
         dict(arrowstyle='->', color='#FFA500', lw=2.0))
    ]
    
    for x, y, text, color, arrow_props in insights:
        plt.annotate(text, 
                   xy=(x, y), 
                   xytext=(x+0.5, y+5),
                   textcoords='data',
                   fontsize=10,
                   fontweight='bold',
                   color=color,
                   bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.95, edgecolor=color),
                   arrowprops=arrow_props,
                   ha='left',
                   va='bottom')

def create_asr_comparison_curved():
    """Create focused curved graph for ASR metrics only"""
    
    plt.figure(figsize=(14, 8))
    
    x_positions = np.arange(len(datasets))
    x_smooth = np.linspace(0, len(datasets)-1, 300)
    
    # ASR metrics only
    asr_metrics = ['NON-STRICT ASR', 'Top Category ASR']
    
    for metric in asr_metrics:
        values = [security_data[dataset][metric] for dataset in datasets]
        
        # Create cubic spline interpolation
        spline = interpolate.CubicSpline(x_positions, values)
        y_smooth = spline(x_smooth)
        
        # Plot the smooth curve
        plt.plot(x_smooth, y_smooth, 
                linewidth=3.0,
                linestyle=metric_line_styles[metric],
                label=metric,
                color=metric_colors[metric],
                alpha=0.9)
        
        # Add markers
        plt.scatter(x_positions, values, 
                   marker=metric_markers[metric],
                   s=100,
                   color=metric_colors[metric],
                   edgecolor='black',
                   linewidth=2.0,
                   zorder=5)
        
        # Add all value annotations for ASR
        for i, (x, y) in enumerate(zip(x_positions, values)):
            plt.annotate(f'{y:.4f}',
                       xy=(x, y),
                       xytext=(x, y + 0.01),
                       textcoords='data',
                       fontsize=10,
                       fontweight='bold',
                       color=metric_colors[metric],
                       ha='center',
                       bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.9, 
                               edgecolor=metric_colors[metric]))
    
    plt.title('', 
              fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('Attack Success Rate', fontsize=13, fontweight='bold')
    plt.xlabel('Dataset Size', fontsize=13, fontweight='bold')
    plt.xticks(x_positions, datasets, fontsize=11)
    plt.ylim(0, 0.25)
    
    # Add horizontal line for reference
    plt.axhline(y=0.05, color='red', linestyle='--', alpha=0.5, label='5% Reference')
    
    plt.grid(True, alpha=0.2, linestyle='--', linewidth=0.5)
    plt.legend(loc='upper right', fontsize=11, frameon=True, fancybox=True, shadow=True)
    
    # Add security achievement annotation
    plt.annotate('✅ STRICT ASR: 0.0000\n(Perfect Security)',
                xy=(2, 0.22), xytext=(3, 0.18),
                arrowprops=dict(arrowstyle='->', color='green', lw=2.0),
                fontsize=12, fontweight='bold', color='green',
                bbox=dict(boxstyle="round,pad=0.4", facecolor='lightgreen', alpha=0.8))
    
    plt.tight_layout()
    
    output_path = Path('results/asr_comparison_curved.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"ASR comparison curved graph saved to: {output_path}")
    
    plt.show()

def create_blocking_layers_curved():
    """Create curved graph for blocking layer distribution"""
    
    plt.figure(figsize=(14, 8))
    
    x_positions = np.arange(len(datasets))
    x_smooth = np.linspace(0, len(datasets)-1, 300)
    
    # Blocking layer metrics
    blocking_metrics = ['L2 Blocking', 'L5 Blocking', 'L3 Blocking']
    
    for metric in blocking_metrics:
        values = [security_data[dataset][metric] for dataset in datasets]
        
        # Create cubic spline interpolation
        spline = interpolate.CubicSpline(x_positions, values)
        y_smooth = spline(x_smooth)
        
        # Plot the smooth curve
        plt.plot(x_smooth, y_smooth, 
                linewidth=2.5,
                linestyle=metric_line_styles[metric],
                label=metric,
                color=metric_colors[metric],
                alpha=0.9)
        
        # Add markers
        plt.scatter(x_positions, values, 
                   marker=metric_markers[metric],
                   s=80,
                   color=metric_colors[metric],
                   edgecolor='black',
                   linewidth=1.5,
                   zorder=5)
        
        # Add value annotations
        for i, (x, y) in enumerate(zip(x_positions, values)):
            if i == 0 or i == len(x_positions)-1:  # First and last points only
                plt.annotate(f'{y:.1f}%',
                           xy=(x, y),
                           xytext=(x, y + 3),
                           textcoords='data',
                           fontsize=9,
                           fontweight='bold',
                           color=metric_colors[metric],
                           ha='center',
                           bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.9, 
                                   edgecolor=metric_colors[metric]))
    
    plt.title('', fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('Blocking Percentage (%)', fontsize=13, fontweight='bold')
    plt.xlabel('Dataset Size', fontsize=13, fontweight='bold')
    plt.xticks(x_positions, datasets, fontsize=11)
    plt.ylim(0, 100)
    
    plt.grid(True, alpha=0.2, linestyle='--', linewidth=0.5)
    plt.legend(loc='upper right', fontsize=11, frameon=True, fancybox=True, shadow=True)
    
    # Add layer effectiveness annotation
    plt.annotate('🛡️ L2: Primary Defense Layer\n(89-90% of attacks blocked)',
                xy=(2, 89), xytext=(3, 75),
                arrowprops=dict(arrowstyle='->', color='#96CEB4', lw=2.0),
                fontsize=11, fontweight='bold', color='#96CEB4',
                bbox=dict(boxstyle="round,pad=0.4", facecolor='lightblue', alpha=0.8))
    
    plt.tight_layout()
    
    output_path = Path('results/blocking_layers_curved.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Blocking layers curved graph saved to: {output_path}")
    
    plt.show()

def create_security_summary_stats():
    """Print summary statistics for security metrics"""
    
    print("\n" + "="*80)
    print("SECURITY METRICS SUMMARY STATISTICS")
    print("="*80)
    
    # Calculate statistics for each metric
    metrics = ['NON-STRICT ASR', 'Top Category ASR', 'L2 Blocking', 'L5 Blocking', 'L3 Blocking']
    
    for metric in metrics:
        values = [security_data[dataset][metric] for dataset in datasets]
        avg = np.mean(values)
        std = np.std(values)
        min_val = min(values)
        max_val = max(values)
        
        print(f"\n📊 {metric}:")
        print(f"   Average: {avg:.4f}{'%' if 'Blocking' in metric else ''}")
        print(f"   Std Dev: {std:.4f}{'%' if 'Blocking' in metric else ''}")
        print(f"   Range: {min_val:.4f} - {max_val:.4f}{'%' if 'Blocking' in metric else ''}")
        print(f"   Stability: {'Excellent' if std < 0.001 else 'Good' if std < 0.01 else 'Moderate'}")
    
    print(f"\n🎯 Key Security Achievement:")
    print(f"   ✅ STRICT ASR: 0.0000 across all datasets (Perfect Security)")
    print(f"   🛡️ Primary Defense: L2 Layer blocks {np.mean([security_data[d]['L2 Blocking'] for d in datasets]):.1f}% of attacks")
    print(f"   ⚠️ Top Attack: instruction_bypass (ASR: {np.mean([security_data[d]['Top Category ASR'] for d in datasets]):.3f})")

if __name__ == "__main__":
    print("Creating curved line graphs for Security Analysis Metrics...")
    print(f"📈 Datasets: {', '.join(datasets)}")
    print("🔄 Lines: Curved (spline interpolation)")
    print("📝 Features: Security insights and value annotations")
    
    create_security_metrics_curved_graph()
    create_asr_comparison_curved()
    create_blocking_layers_curved()
    create_security_summary_stats()
    
    print("\n✅ COMPLETED! Security metrics graphs created with:")
    print("   - Smooth curved lines for all metrics")
    print("   - Security insights and annotations")
    print("   - Value labels on key data points")
    print("   - Focused ASR and blocking layer analysis")
    print("   - Professional security-focused visualization")
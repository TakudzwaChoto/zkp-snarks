"""
Create line graphs with ALL methods and ALL datasets using curved lines and statistical annotations
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from scipy import interpolate

# Complete data with all methods for all datasets
data = {
    '4k': {
        'ZKP Framework': [0.909, 0.919, 0.886, 0.902, 0.886, 0.930, 0.09, 662653, 0.867, 0.886, 1584, 1860, 140, 204],
        'Regex Baseline': [0.911, 0.919, 0.890, 0.905, 0.890, 0.930, 0.06, 979820, 0.867, 0.890, 1592, 1860, 140, 196],
        'LLM Simulator': [0.812, 1.000, 0.602, 0.752, 0.602, 1.000, 0.07, 871892, 0.578, 0.602, 1077, 2000, 0, 711],
        'Fusion Engine ': [0.935, 0.923, 0.940, 0.932, 0.940, 0.930, 0.24, 253058, 0.921, 0.940, 1681, 1860, 140, 107]
    },
    '6k': {
        'ZKP Framework': [0.907, 0.917, 0.884, 0.900, 0.884, 0.928, 0.09, 670886, 0.864, 0.884, 2378, 2785, 215, 312],
        'Regex Baseline': [0.908, 0.917, 0.885, 0.901, 0.885, 0.928, 0.06, 1019427, 0.860, 0.885, 2380, 2785, 215, 310],
        'LLM Simulator': [0.813, 1.000, 0.605, 0.754, 0.605, 1.000, 0.07, 899652, 0.590, 0.605, 1627, 3000, 0, 1063],
        'Fusion Engine ': [0.933, 0.922, 0.938, 0.930, 0.938, 0.928, 0.23, 261165, 0.919, 0.938, 2524, 2785, 215, 166]
    },
    '50k': {
        'ZKP Framework': [0.908, 0.919, 0.885, 0.902, 0.885, 0.930, 0.09, 663641, 0.864, 0.885, 19951, 23244, 1756, 2595],
        'Regex Baseline': [0.907, 0.919, 0.881, 0.900, 0.881, 0.930, 0.06, 989538, 0.854, 0.881, 19864, 23244, 1756, 2682],
        'LLM Simulator': [0.815, 1.000, 0.610, 0.757, 0.610, 1.000, 0.07, 829689, 0.584, 0.610, 13745, 25000, 0, 8801],
        'Fusion Engine ': [0.935, 0.923, 0.940, 0.932, 0.940, 0.930, 0.23, 256912, 0.924, 0.940, 21198, 23244, 1756, 1348]
    },
    '120k': {
        'ZKP Framework': [0.910, 0.919, 0.887, 0.903, 0.887, 0.930, 0.09, 667140, 0.875, 0.887, 47805, 55809, 4191, 6072],
        'Regex Baseline': [0.907, 0.919, 0.882, 0.900, 0.882, 0.930, 0.06, 927862, 0.864, 0.882, 47534, 55809, 4191, 6343],
        'LLM Simulator': [0.816, 1.000, 0.611, 0.759, 0.611, 1.000, 0.07, 913634, 0.592, 0.611, 32934, 60000, 0, 20943],
        'Fusion Engine ': [0.935, 0.924, 0.940, 0.932, 0.940, 0.930, 0.24, 251400, 0.924, 0.940, 50670, 55809, 4191, 3207]
    },
    '200k': {
        'ZKP Framework': [0.910, 0.920, 0.886, 0.903, 0.886, 0.930, 0.09, 645945, 0.868, 0.886, 79653, 93043, 6957, 10202],
        'Regex Baseline': [0.907, 0.919, 0.882, 0.900, 0.882, 0.930, 0.07, 893379, 0.858, 0.882, 79231, 93043, 6957, 10624],
        'LLM Simulator': [0.814, 1.000, 0.608, 0.756, 0.608, 1.000, 0.07, 905492, 0.589, 0.608, 54608, 100000, 0, 35247],
        'Fusion Engine ': [0.935, 0.924, 0.940, 0.932, 0.940, 0.930, 0.23, 256405, 0.928, 0.940, 84455, 93043, 6957, 5400]
    }
}

# All 14 features
metrics = [
    'Accuracy', 'Precision', 'Recall', 'F1-Score', 'Sensitivity', 'Specificity',
    'Latency (ms)', 'Throughput (RPM)', 'Tamper Res.', 'Detection Rate',
    'TP', 'TN', 'FP', 'FN'
]

datasets = ['4k', '6k', '50k', '120k', '200k']
methods = ['ZKP Framework', 'Regex Baseline', 'LLM Simulator', 'Fusion Engine ']

# Very distinct colors for each METHOD
method_colors = {
    'ZKP Framework': '#FF0000',    # Bright Red
    'Regex Baseline': '#0000FF',   # Bright Blue  
    'LLM Simulator': '#00FF00',    # Bright Green
    'Fusion Engine ': '#FF00FF'          # Magenta
}

# Different line styles for datasets
dataset_line_styles = {
    '4k': '-',      # Solid
    '6k': '--',     # Dashed
    '50k': '-.',    # Dash-dot
    '120k': ':',    # Dotted
    '200k': (0, (3, 1, 1, 1))  # Custom dash
}

# Marker styles for additional distinction
dataset_markers = {
    '4k': 'o',  # Circle
    '6k': 's',  # Square
    '50k': '^', # Triangle up
    '120k': 'D', # Diamond
    '200k': 'v'  # Triangle down
}

def normalize_for_line_graph(original_values, dataset_size):
    """Normalize values for line graph visualization"""
    normalized = []
    
    for i, value in enumerate(original_values):
        if i < 6:  # Performance metrics (0-1)
            normalized.append(value)
        elif i == 6:  # Latency (reverse scale)
            normalized.append(max(0, 1 - (value / 0.3)))  # 0ms = 1.0, 0.3ms = 0.0
        elif i == 7:  # Throughput
            normalized.append(min(1, value / 1200000))  # Normalize to max ~1.2M RPM
        elif i in [8, 9]:  # Tamper Resistance, Detection Rate
            normalized.append(value)
        else:  # Count metrics
            if i in [10, 11]:  # TP, TN
                normalized.append(value / dataset_size)
            else:  # FP, FN (reverse)
                normalized.append(max(0, 1 - (value / (dataset_size * 0.5))))
    
    return normalized

def create_curved_line_with_stats():
    """Create comprehensive comparison with curved lines and statistical annotations"""
    
    plt.figure(figsize=(20, 10))
    
    x_positions = np.arange(len(metrics))
    dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
    
    # Create smooth curves using spline interpolation
    x_smooth = np.linspace(0, len(metrics)-1, 300)
    
    # Plot all methods for all datasets with CURVED lines
    for dataset in datasets:
        for method in methods:
            values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
            
            # Create cubic spline interpolation for smooth curves
            spline = interpolate.CubicSpline(x_positions, values)
            y_smooth = spline(x_smooth)
            
            # Plot the smooth curve
            line = plt.plot(x_smooth, y_smooth, 
                    linewidth=1.5,
                    linestyle=dataset_line_styles[dataset],
                    label=f'{dataset} - {method}',
                    color=method_colors[method],
                    alpha=0.8)[0]
            
            # Add markers at original data points
            plt.scatter(x_positions, values, 
                       marker=dataset_markers[dataset],
                       s=40,  # Marker size
                       color=method_colors[method],
                       edgecolor='black',
                       linewidth=0.8,
                       zorder=5)  # Ensure markers are on top
    
    # Add statistical annotations for key metrics
    add_statistical_annotations()
    
    plt.title('', 
              fontsize=18, fontweight='bold', pad=25)
    plt.ylabel('Normalized Score (0-1)', fontsize=14, fontweight='bold')
    plt.xlabel('Features', fontsize=14, fontweight='bold')
    plt.xticks(x_positions, metrics, rotation=45, ha='right', fontsize=11)
    plt.ylim(0, 1.1)
    plt.grid(True, alpha=0.2, linestyle='--', linewidth=0.5)
    
    # Enhanced legend
    legend = plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=10, ncol=2,
                       frameon=True, fancybox=True, shadow=True, framealpha=0.95)
    
    plt.tight_layout()
    
    output_path = Path('results/curved_lines_with_stats.png')
    output_path.parent.mkdir(exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Curved lines graph with stats saved to: {output_path}")
    
    plt.show()

def add_statistical_annotations():
    """Add statistical annotations to the graph"""
    
    # Key insights to annotate
    insights = [
        # (x_position, y_position, text, color, arrow_props)
        (0, 0.94, "Fusion Engine : Highest Accuracy\nacross all datasets", '#FF00FF', dict(arrowstyle='->', color='#FF00FF', lw=1.5)),
        (1, 1.02, "LLM: Perfect Precision\nbut trade-off in Recall", '#00FF00', dict(arrowstyle='->', color='#00FF00', lw=1.5)),
        (6, 0.75, "Regex: Best Latency &\nThroughput", '#0000FF', dict(arrowstyle='->', color='#0000FF', lw=1.5)),
        (2, 0.85, "ZKP: Consistent Performance\nacross all metrics", '#FF0000', dict(arrowstyle='->', color='#FF0000', lw=1.5)),
        (9, 0.96, "Fusion Engine : Best Detection Rate\n& Tamper Resistance", '#FF00FF', dict(arrowstyle='->', color='#FF00FF', lw=1.5)),
    ]
    
    for x, y, text, color, arrow_props in insights:
        plt.annotate(text, 
                   xy=(x, y), 
                   xytext=(x+1, min(y+0.1, 1.0)),
                   textcoords='data',
                   fontsize=10,
                   fontweight='bold',
                   color=color,
                   bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.9, edgecolor=color),
                   arrowprops=arrow_props,
                   ha='left',
                   va='bottom')

def create_method_curved_comparison():
    """Create curved line comparison for each method across datasets"""
    
    # Create one graph per method showing performance across all datasets with curved lines
    for method in methods:
        plt.figure(figsize=(18, 8))
        
        x_positions = np.arange(len(metrics))
        dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
        x_smooth = np.linspace(0, len(metrics)-1, 300)
        
        # Distinct colors for datasets within each method
        dataset_colors_method = {
            '4k': '#FF6B6B',    # Red
            '6k': '#4ECDC4',    # Teal  
            '50k': '#45B7D1',   # Blue
            '120k': '#96CEB4',  # Green
            '200k': '#FFA500'   # Orange
        }
        
        for dataset in datasets:
            values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
            
            # Create smooth curve
            spline = interpolate.CubicSpline(x_positions, values)
            y_smooth = spline(x_smooth)
            
            plt.plot(x_smooth, y_smooth, 
                    linewidth=2.0,
                    label=f'{dataset} Dataset',
                    color=dataset_colors_method[dataset],
                    alpha=0.9)
            
            # Add markers at data points
            plt.scatter(x_positions, values,
                       marker=dataset_markers[dataset],
                       s=50,
                       color=dataset_colors_method[dataset],
                       edgecolor='black',
                       linewidth=1.0,
                       zorder=5)
            
            # Add dataset-specific stats on the lines
            add_dataset_stats(x_positions, values, dataset, dataset_colors_method[dataset])
        
        plt.title(f'{method} ', 
                  fontsize=16, fontweight='bold', pad=20)
        plt.ylabel('Normalized Score (0-1)', fontsize=12, fontweight='bold')
        plt.xlabel('Features', fontsize=12, fontweight='bold')
        plt.xticks(x_positions, metrics, rotation=45, ha='right', fontsize=10)
        plt.ylim(0, 1.1)
        plt.grid(True, alpha=0.2, linestyle='--', linewidth=0.5)
        
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=11)
        
        plt.tight_layout()
        
        output_path = Path(f'results/{method.replace(" ", "_").lower()}_curved_comparison.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"{method} curved comparison saved to: {output_path}")
        
        plt.show()

def add_dataset_stats(x_positions, values, dataset, color):
    """Add statistical annotations for each dataset"""
    
    # Add key value annotations for important metrics
    key_metrics = [0, 1, 3, 6, 9]  # Accuracy, Precision, F1, Latency, Detection Rate
    
    for idx in key_metrics:
        if idx < len(values):
            x = x_positions[idx]
            y = values[idx]
            
            # Format the value based on metric type
            if idx in [0, 1, 3, 9]:  # Percentage-like metrics
                value_text = f'{values[idx]:.3f}'
            elif idx == 6:  # Latency (reverse normalized)
                original_latency = 0.3 * (1 - values[idx])  # Reverse calculation
                value_text = f'{original_latency:.2f}ms'
            else:
                value_text = f'{values[idx]:.2f}'
            
            # Position the text to avoid overlap
            text_y = y + 0.03 if y < 0.9 else y - 0.03
            
            plt.annotate(value_text,
                       xy=(x, y),
                       xytext=(x, text_y),
                       textcoords='data',
                       fontsize=8,
                       fontweight='bold',
                       color=color,
                       ha='center',
                       bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.8, edgecolor=color))

def create_ensemble_highlight_curved():
    """Create curved line graph highlighting Ensemble method performance"""
    
    plt.figure(figsize=(18, 9))
    
    x_positions = np.arange(len(metrics))
    dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
    x_smooth = np.linspace(0, len(metrics)-1, 300)
    
    # Plot all methods for 50k dataset (representative) with curved lines
    for method in methods:
        values = normalize_for_line_graph(data['50k'][method], dataset_sizes['50k'])
        
        spline = interpolate.CubicSpline(x_positions, values)
        y_smooth = spline(x_smooth)
        
        linewidth = 3.0 if method == 'Fusion Engine ' else 1.5
        alpha = 1.0 if method == 'Fusion Engine ' else 0.7
        
        plt.plot(x_smooth, y_smooth, 
                linewidth=linewidth,
                label=method,
                color=method_colors[method],
                alpha=alpha)
        
        # Add markers
        plt.scatter(x_positions, values,
                   marker='o' if method == 'Fusion Engine ' else 's',
                   s=60 if method == 'Fusion Engine ' else 40,
                   color=method_colors[method],
                   edgecolor='black',
                   linewidth=1.0 if method == 'Fusion Engine ' else 0.5,
                   zorder=5)
    
    # Add performance comparison annotations
    plt.annotate('🏆 Fusion Engine : Best Overall Balance', 
                xy=(3, 0.94), xytext=(5, 1.02),
                arrowprops=dict(arrowstyle='->', color='#FF00FF', lw=2.0),
                fontsize=12, fontweight='bold', color='#FF00FF')
    
    plt.annotate('⚡ Regex: Speed Champion', 
                xy=(7, 0.92), xytext=(9, 0.82),
                arrowprops=dict(arrowstyle='->', color='#0000FF', lw=1.5),
                fontsize=11, fontweight='bold', color='#0000FF')
    
    plt.annotate('🎯 LLM: Precision Expert', 
                xy=(1, 1.0), xytext=(2, 0.75),
                arrowprops=dict(arrowstyle='->', color='#00FF00', lw=1.5),
                fontsize=11, fontweight='bold', color='#00FF00')
    
    plt.title('', 
              fontsize=18, fontweight='bold', pad=25)
    plt.ylabel('Normalized Score (0-1)', fontsize=14, fontweight='bold')
    plt.xlabel('Features', fontsize=14, fontweight='bold')
    plt.xticks(x_positions, metrics, rotation=45, ha='right', fontsize=11)
    plt.ylim(0, 1.1)
    plt.grid(True, alpha=0.2, linestyle='--', linewidth=0.5)
    
    plt.legend(loc='lower right', fontsize=12, frameon=True, fancybox=True, shadow=True)
    
    plt.tight_layout()
    
    output_path = Path('results/Fusion Engine _curved.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Fusion Engine  highlight curved graph saved to: {output_path}")
    
    plt.show()

if __name__ == "__main__":
    print("Creating curved line graphs with statistical annotations...")
    print(f"📊 Methods: {', '.join(methods)}")
    print(f"📈 Datasets: {', '.join(datasets)}")
    print("🔄 Lines: Curved (spline interpolation)")
    print("📝 Features: Statistical annotations and value labels")
    
    create_curved_line_with_stats()
    create_method_curved_comparison()
    create_ensemble_highlight_curved()
    
    print("\n✅ COMPLETED! All curved graphs created with:")
    print("   - Smooth curved lines (spline interpolation)")
    print("   - Statistical annotations and insights")
    print("   - Value labels on key metrics")
    print("   - Performance highlights and comparisons")
    print("   - Clean, professional visualization")
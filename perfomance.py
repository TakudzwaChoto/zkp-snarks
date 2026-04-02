"""
Create line graphs with ALL methods and ALL datasets using curved lines and statistical annotations
All features shown clearly for ALL datasets with non-overlapping labels
"""

import pandas as pd
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
from pathlib import Path
from scipy import interpolate
from scipy.interpolate import CubicSpline
import matplotlib.cm as cm
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
import matplotlib.patheffects as path_effects

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

# All 14 features - with clear labels
metrics = [
    'Accuracy', 'Precision', 'Recall', 'F1-Score', 'Sensitivity', 'Specificity',
    'Latency\n(ms)', 'Throughput\n(RPM)', 'Tamper\nRes.', 'Detection\nRate',
    'TP', 'TN', 'FP', 'FN'
]

datasets = ['4k', '6k', '50k', '120k', '200k']
methods = ['ZKP Framework', 'Regex Baseline', 'LLM Simulator', 'Fusion Engine ']

# Very distinct colors for each METHOD
method_colors = {
    'ZKP Framework': '#FF0000',    # Bright Red
    'Regex Baseline': '#0000FF',   # Bright Blue  
    'LLM Simulator': '#00FF00',    # Bright Green
    'Fusion Engine ': '#FF00FF'    # Magenta
}

# Different line styles for datasets
dataset_line_styles = {
    '4k': '-',      # Solid
    '6k': '--',     # Dashed
    '50k': '-.',    # Dash-dot
    '120k': ':',    # Dotted
    '200k': (0, (3, 1, 1, 1))  # Custom dash
}

# Marker styles for datasets
dataset_markers = {
    '4k': 'o',      # Circle
    '6k': 's',      # Square
    '50k': '^',     # Triangle up
    '120k': 'D',    # Diamond
    '200k': 'v'     # Triangle down
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
                normalized.append(min(1, value / dataset_size))
            else:  # FP, FN (reverse)
                normalized.append(max(0, 1 - min(1, value / (dataset_size * 0.5))))
    
    return normalized

def get_original_value(normalized_value, metric_idx, dataset_size):
    """Convert normalized value back to original for display"""
    if metric_idx < 6:  # Performance metrics
        return normalized_value
    elif metric_idx == 6:  # Latency
        return 0.3 * (1 - normalized_value)
    elif metric_idx == 7:  # Throughput
        return normalized_value * 1200000
    elif metric_idx in [8, 9]:  # Tamper Resistance, Detection Rate
        return normalized_value
    elif metric_idx in [10, 11]:  # TP, TN
        return normalized_value * dataset_size
    else:  # FP, FN
        return dataset_size * 0.5 * (1 - normalized_value)

# ================== 2D CURVED LINE FOR ALL DATASETS ==================

def create_curved_line_all_datasets():
    """Create comprehensive comparison with ALL datasets and ALL features"""
    
    # Large figure to accommodate all information
    fig = plt.figure(figsize=(28, 16))
    ax = plt.gca()
    
    x_positions = np.arange(len(metrics))
    dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
    
    # Create smooth curves
    x_smooth = np.linspace(0, len(metrics)-1, 500)
    
    # Store legend handles
    method_handles = []
    dataset_handles = []
    
    # Plot ALL methods for ALL datasets
    line_alpha = 0.6  # Slightly transparent to see overlapping lines
    
    for method in methods:
        for dataset in datasets:
            values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
            
            # Create cubic spline
            spline = interpolate.CubicSpline(x_positions, values, bc_type='natural')
            y_smooth = spline(x_smooth)
            
            # Plot curve
            line, = ax.plot(x_smooth, y_smooth, 
                          linewidth=1.8,
                          linestyle=dataset_line_styles[dataset],
                          color=method_colors[method],
                          alpha=line_alpha,
                          zorder=1)
            
            # Add markers at data points
            ax.scatter(x_positions, values,
                      marker=dataset_markers[dataset],
                      s=60,
                      color=method_colors[method],
                      edgecolor='white',
                      linewidth=0.8,
                      alpha=0.9,
                      zorder=2)
    
    # Add value labels for key points (strategically placed)
    add_all_dataset_labels(ax, x_positions, dataset_sizes)
    
    # Add metric group backgrounds
    add_metric_backgrounds(ax, x_positions)
    
    # Create legends
    # Method legend
    method_handles = [Patch(facecolor=method_colors[m], alpha=0.8, label=m.strip()) 
                     for m in methods]
    method_legend = ax.legend(handles=method_handles, loc='upper left', 
                             bbox_to_anchor=(0.01, 0.99), fontsize=11,
                             frameon=True, fancybox=True, shadow=True,
                             title="Methods", title_fontsize=12)
    
    # Dataset legend
    dataset_handles = []
    for dataset in datasets:
        handle = Line2D([0], [0], linestyle=dataset_line_styles[dataset], 
                       color='black', linewidth=2, 
                       marker=dataset_markers[dataset], markersize=8,
                       label=f'{dataset}')
        dataset_handles.append(handle)
    
    dataset_legend = ax.legend(handles=dataset_handles, loc='upper left',
                               bbox_to_anchor=(0.15, 0.99), fontsize=11,
                               frameon=True, fancybox=True, shadow=True,
                               title="Datasets", title_fontsize=12)
    
    ax.add_artist(method_legend)
    ax.add_artist(dataset_legend)
    
    # Title and labels
    ax.set_title('Performance Comparison: All Methods Across All Datasets\n(All 14 Features Displayed)', 
                fontsize=18, fontweight='bold', pad=40)
    ax.set_ylabel('Normalized Performance Score (0-1)', fontsize=14, fontweight='bold', labelpad=15)
    ax.set_xlabel('Features', fontsize=14, fontweight='bold', labelpad=15)
    
    # X-axis - ALL features shown
    ax.set_xticks(x_positions)
    ax.set_xticklabels(metrics, rotation=45, ha='right', fontsize=10)
    
    # Y-axis
    ax.set_ylim(-0.05, 1.15)
    ax.set_yticks(np.arange(0, 1.1, 0.1))
    ax.set_yticklabels([f'{x:.1f}' for x in np.arange(0, 1.1, 0.1)], fontsize=10)
    
    # Grid
    ax.grid(True, alpha=0.15, linestyle='--', linewidth=0.5)
    
    # Add summary statistics box
    add_summary_box(ax)
    
    plt.tight_layout()
    
    # Save
    output_path = Path('results/curved_lines_all_datasets_all_features.png')
    output_path.parent.mkdir(exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Curved lines with ALL datasets saved to: {output_path}")
    
    plt.show()
    return fig

def add_all_dataset_labels(ax, x_positions, dataset_sizes):
    """Add value labels for ALL datasets with careful positioning"""
    
    # Define label positions for each metric (which methods to label at each x)
    label_strategy = {
        0: ['Fusion Engine ', 'ZKP Framework'],  # Accuracy
        1: ['LLM Simulator', 'Regex Baseline'],   # Precision
        2: ['Fusion Engine ', 'ZKP Framework'],   # Recall
        3: ['Fusion Engine ', 'ZKP Framework'],   # F1-Score
        4: ['Fusion Engine ', 'ZKP Framework'],   # Sensitivity
        5: ['LLM Simulator', 'Fusion Engine '],   # Specificity
        6: ['Regex Baseline', 'ZKP Framework'],   # Latency
        7: ['Regex Baseline', 'LLM Simulator'],   # Throughput
        8: ['Fusion Engine ', 'ZKP Framework'],   # Tamper Res
        9: ['Fusion Engine ', 'ZKP Framework'],   # Detection Rate
        10: ['Fusion Engine ', 'Regex Baseline'],  # TP
        11: ['Fusion Engine ', 'ZKP Framework'],  # TN
        12: ['Fusion Engine ', 'ZKP Framework'],  # FP
        13: ['Fusion Engine ', 'ZKP Framework'],  # FN
    }
    
    # Vertical offsets for different datasets at same x position
    dataset_offsets = {
        '4k': 0.03,
        '6k': 0.015,
        '50k': 0,
        '120k': -0.015,
        '200k': -0.03,
    }
    
    # Horizontal offsets for different methods at same x
    method_offsets = {
        'ZKP Framework': -0.1,
        'Regex Baseline': -0.05,
        'LLM Simulator': 0.05,
        'Fusion Engine ': 0.1,
    }
    
    for metric_idx in range(len(metrics)):
        x = x_positions[metric_idx]
        methods_to_label = label_strategy.get(metric_idx, ['Fusion Engine ', 'ZKP Framework'])
        
        for method in methods_to_label:
            for dataset in datasets:
                # Get values
                values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
                norm_val = values[metric_idx]
                orig_val = get_original_value(norm_val, metric_idx, dataset_sizes[dataset])
                
                # Format label
                if metric_idx < 6:  # 0-1 metrics
                    label = f'{norm_val:.3f}'
                elif metric_idx == 6:  # Latency
                    label = f'{orig_val:.2f}ms'
                elif metric_idx == 7:  # Throughput
                    label = f'{orig_val/1000:.0f}K'
                elif metric_idx in [8, 9]:  # Security metrics
                    label = f'{norm_val:.3f}'
                else:  # Counts
                    if orig_val > 1000:
                        label = f'{orig_val/1000:.0f}K'
                    else:
                        label = f'{orig_val:.0f}'
                
                # Calculate position with offsets
                x_pos = x + method_offsets.get(method, 0)
                y_pos = norm_val + dataset_offsets.get(dataset, 0)
                
                # Determine label color
                if dataset in ['4k', '6k']:
                    bg_color = '#FFF5E6'
                elif dataset in ['50k']:
                    bg_color = '#E6F3FF'
                else:
                    bg_color = '#F0E6FF'
                
                # Add label with leader line
                ax.plot([x, x_pos], [norm_val, y_pos], 
                       color=method_colors[method], linewidth=0.5, alpha=0.3, zorder=1)
                
                ax.text(x_pos, y_pos, label,
                       fontsize=7, fontweight='bold',
                       color=method_colors[method],
                       ha='center', va='center',
                       bbox=dict(boxstyle="round,pad=0.2", 
                                facecolor=bg_color, alpha=0.9,
                                edgecolor=method_colors[method], linewidth=0.5),
                       path_effects=[path_effects.withStroke(linewidth=2, foreground='white')],
                       zorder=3)

def add_metric_backgrounds(ax, x_positions):
    """Add subtle background colors to group related metrics"""
    
    groups = [
        (0, 5, '#FFE5E5', 'Classification Metrics'),      # Accuracy to Specificity
        (6, 7, '#E5FFE5', 'Performance Metrics'),         # Latency, Throughput
        (8, 9, '#E5E5FF', 'Security Metrics'),            # Tamper Res, Detection Rate
        (10, 13, '#FFFFE5', 'Confusion Matrix Counts')    # TP to FN
    ]
    
    y_min, y_max = ax.get_ylim()
    
    for start, end, color, label in groups:
        ax.axvspan(start - 0.4, end + 0.4, alpha=0.1, color=color, zorder=0)
        
        # Add group label at the top
        mid = (start + end) / 2
        ax.text(mid, y_max * 0.98, label, 
               fontsize=10, fontweight='bold', ha='center', va='top',
               color='gray', alpha=0.7,
               bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.7))

def add_summary_box(ax):
    """Add summary statistics box"""
    
    # Calculate average improvements
    improvements = []
    for dataset in datasets:
        for i, metric in enumerate(metrics[:6]):  # Only performance metrics
            zkp_val = normalize_for_line_graph(data[dataset]['ZKP Framework'], 4000)[i]
            fusion_val = normalize_for_line_graph(data[dataset]['Fusion Engine '], 4000)[i]
            improvements.append(fusion_val - zkp_val)
    
    avg_improvement = np.mean(improvements) * 100
    
    summary_text = f"""KEY INSIGHTS:
    • Fusion Engine shows {avg_improvement:.1f}% avg improvement
    • LLM perfect precision (1.000) on all datasets
    • Regex fastest latency (0.06-0.07ms)
    • All 14 features displayed clearly"""
    
    ax.text(0.98, 0.02, summary_text,
           transform=ax.transAxes,
           fontsize=10,
           verticalalignment='bottom',
           horizontalalignment='right',
           bbox=dict(boxstyle="round,pad=0.5", 
                    facecolor='white', alpha=0.95,
                    edgecolor='gray', linewidth=1))

# ================== METHOD-SPECIFIC COMPARISONS ==================

def create_method_comparisons_all_datasets():
    """Create separate plots for each method showing ALL datasets"""
    
    for method in methods:
        fig, axes = plt.subplots(2, 1, figsize=(22, 14))
        ax1, ax2 = axes
        
        x_positions = np.arange(len(metrics))
        dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
        x_smooth = np.linspace(0, len(metrics)-1, 300)
        
        # Colors for datasets
        dataset_colors = {
            '4k': '#FF6B6B',    # Red
            '6k': '#4ECDC4',    # Teal
            '50k': '#45B7D1',   # Blue
            '120k': '#96CEB4',  # Green
            '200k': '#FFA500'   # Orange
        }
        
        # Main plot - curved lines
        for dataset in datasets:
            values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
            
            # Smooth curve
            spline = CubicSpline(x_positions, values, bc_type='natural')
            y_smooth = spline(x_smooth)
            
            ax1.plot(x_smooth, y_smooth, 
                    linewidth=2.5,
                    label=f'{dataset}',
                    color=dataset_colors[dataset],
                    alpha=0.9)
            
            # Markers
            ax1.scatter(x_positions, values,
                       marker='o',
                       s=100,
                       color=dataset_colors[dataset],
                       edgecolor='black',
                       linewidth=1,
                       zorder=5)
        
        ax1.set_title(f'{method.strip()} - Performance Across All Datasets (Curved Lines)', 
                     fontsize=16, fontweight='bold', pad=20)
        ax1.set_ylabel('Normalized Score (0-1)', fontsize=12, fontweight='bold')
        ax1.set_xticks(x_positions)
        ax1.set_xticklabels(metrics, rotation=45, ha='right', fontsize=9)
        ax1.set_ylim(0, 1.1)
        ax1.grid(True, alpha=0.2)
        ax1.legend(loc='upper right', fontsize=10, title='Datasets')
        
        # Subplot - actual values
        x = np.arange(len(metrics))
        width = 0.15
        
        for i, dataset in enumerate(datasets):
            values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
            offset = width * (i - 2)
            bars = ax2.bar(x + offset, values, width, 
                          label=dataset, color=dataset_colors[dataset], alpha=0.8)
            
            # Add value labels on bars
            for j, (bar, val) in enumerate(zip(bars, values)):
                if val > 0.05:  # Only label if bar is tall enough
                    height = bar.get_height()
                    ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                            f'{val:.2f}', ha='center', va='bottom', 
                            fontsize=7, rotation=90)
        
        ax2.set_title(f'{method.strip()} - Actual Normalized Values', 
                     fontsize=14, fontweight='bold', pad=20)
        ax2.set_ylabel('Normalized Score', fontsize=12, fontweight='bold')
        ax2.set_xlabel('Features', fontsize=12, fontweight='bold')
        ax2.set_xticks(x)
        ax2.set_xticklabels(metrics, rotation=45, ha='right', fontsize=9)
        ax2.set_ylim(0, 1.2)
        ax2.grid(True, alpha=0.2, axis='y')
        ax2.legend(loc='upper right', fontsize=9)
        
        plt.tight_layout()
        
        # Save
        output_path = Path(f'results/{method.replace(" ", "_").lower()}_all_datasets.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"{method.strip()} comparison saved to: {output_path}")
        
        plt.show()

# ================== 3D VISUALIZATIONS FOR ALL DATASETS ==================

def create_3d_all_datasets_comparison():
    """Create 3D visualization showing ALL datasets and ALL features"""
    
    fig = plt.figure(figsize=(24, 14))
    ax = fig.add_subplot(111, projection='3d')
    
    dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
    dataset_indices = np.arange(len(datasets))
    metric_indices = np.arange(len(metrics))
    
    # Create mesh
    X, Y = np.meshgrid(metric_indices, dataset_indices)
    
    # Plot surface for each method with different offset
    for method_idx, method in enumerate(methods):
        Z_data = np.zeros((len(datasets), len(metrics)))
        
        for i, dataset in enumerate(datasets):
            values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
            Z_data[i, :] = values
        
        # Add offset for visibility
        offset = method_idx * 1.2
        Z_offset = Z_data + offset
        
        # Plot surface
        surf = ax.plot_surface(X, Y, Z_offset, alpha=0.6, 
                              cmap=plt.cm.Spectral if method_idx == 0 else None,
                              linewidth=0.5, edgecolor='black')
        
        # Add method label
        ax.text(len(metrics)-1, len(datasets)-1, offset + 0.5, 
                method.strip(), color='black', fontsize=12, fontweight='bold',
                bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.9))
    
    # Labels
    ax.set_xlabel('Metrics', fontsize=12, labelpad=20)
    ax.set_ylabel('Datasets', fontsize=12, labelpad=20)
    ax.set_zlabel('Normalized Score (+ offset)', fontsize=12, labelpad=20)
    ax.set_title('3D Visualization: All Methods, All Datasets, All Features', 
                fontsize=16, fontweight='bold', pad=30)
    
    # X-axis - all metrics
    ax.set_xticks(metric_indices)
    ax.set_xticklabels([m.replace('\n', ' ') for m in metrics], 
                       rotation=45, ha='right', fontsize=8)
    
    # Y-axis - all datasets
    ax.set_yticks(dataset_indices)
    ax.set_yticklabels(datasets, fontsize=10)
    
    # Legend for methods
    legend_elements = [Patch(facecolor=plt.cm.Spectral(i/len(methods)), alpha=0.7, label=m.strip()) 
                      for i, m in enumerate(methods)]
    ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0.02, 0.98),
             fontsize=10, frameon=True)
    
    # Set view
    ax.view_init(elev=25, azim=45)
    
    plt.tight_layout()
    
    output_path = Path('results/3d_all_datasets_all_features.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"3D visualization saved to: {output_path}")
    
    plt.show()
    return fig

def create_3d_bar_all_datasets():
    """Create 3D bar chart showing all datasets clearly"""
    
    fig = plt.figure(figsize=(28, 16))
    ax = fig.add_subplot(111, projection='3d')
    
    dataset_sizes = {'4k': 4000, '6k': 6000, '50k': 50000, '120k': 120000, '200k': 200000}
    
    # Positions
    x = np.arange(len(methods))
    y = np.arange(len(datasets))
    x, y = np.meshgrid(x, y)
    x = x.flatten()
    y = y.flatten()
    z = np.zeros_like(x)
    
    # Bar dimensions
    dx = 0.2
    dy = 0.2
    
    # Colors by dataset
    dataset_colors_map = plt.cm.Set1(np.linspace(0, 1, len(datasets)))
    
    # Plot bars for a few key metrics (to avoid overcrowding)
    key_metrics = [0, 3, 6, 7, 9]  # Accuracy, F1, Latency, Throughput, Detection Rate
    metric_names = [metrics[i] for i in key_metrics]
    
    for metric_idx, metric_name in zip(key_metrics, metric_names):
        fig = plt.figure(figsize=(24, 14))
        ax = fig.add_subplot(111, projection='3d')
        
        dz_values = []
        colors = []
        
        for i, dataset in enumerate(datasets):
            for j, method in enumerate(methods):
                values = normalize_for_line_graph(data[dataset][method], dataset_sizes[dataset])
                dz = values[metric_idx]
                dz_values.append(dz)
                colors.append(dataset_colors_map[i])
        
        # Plot bars
        bars = ax.bar3d(x, y, z, dx, dy, dz_values, 
                        color=colors, alpha=0.8, shade=True)
        
        # Add value labels
        for xi, yi, zi in zip(x, y, dz_values):
            if zi > 0.1:
                ax.text(xi + dx/2, yi + dy/2, zi + 0.02, 
                       f'{zi:.2f}', fontsize=7, ha='center', va='bottom',
                       fontweight='bold')
        
        # Labels
        ax.set_xlabel('Methods', fontsize=12, labelpad=15)
        ax.set_ylabel('Datasets', fontsize=12, labelpad=15)
        ax.set_zlabel('Normalized Score', fontsize=12, labelpad=15)
        ax.set_title(f'3D Bar Chart: {metric_name} - All Methods, All Datasets', 
                    fontsize=14, fontweight='bold', pad=20)
        
        # X-axis
        ax.set_xticks(np.arange(len(methods)) + dx/2)
        ax.set_xticklabels([m.strip() for m in methods], rotation=30, fontsize=9)
        
        # Y-axis
        ax.set_yticks(np.arange(len(datasets)) + dy/2)
        ax.set_yticklabels(datasets, fontsize=9)
        
        # Z-axis
        ax.set_zlim(0, 1.1)
        
        # Legend for datasets
        legend_elements = [Patch(facecolor=dataset_colors_map[i], alpha=0.8, label=d) 
                          for i, d in enumerate(datasets)]
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0.02, 0.98),
                 fontsize=9, frameon=True)
        
        # View
        ax.view_init(elev=30, azim=45)
        
        plt.tight_layout()
        
        # Save
        output_path = Path(f'results/3d_bar_{metric_name.replace(" ", "_").lower()}_all_datasets.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"3D bar chart for {metric_name} saved to: {output_path}")
        
        plt.show()

# ================== HEATMAP FOR ALL DATASETS ==================

def create_heatmap_all_datasets():
    """Create heatmap showing performance across all datasets and methods"""
    
    # For each dataset, create a heatmap
    for dataset in datasets:
        fig, ax = plt.subplots(figsize=(16, 10))
        
        # Prepare data
        data_matrix = []
        method_names = []
        
        for method in methods:
            values = normalize_for_line_graph(data[dataset][method], 4000)
            data_matrix.append(values[:10])  # First 10 metrics (0-1 scale)
            method_names.append(method.strip())
        
        data_matrix = np.array(data_matrix)
        
        # Create heatmap
        im = ax.imshow(data_matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
        
        # Add value annotations
        for i in range(len(methods)):
            for j in range(10):
                text = ax.text(j, i, f'{data_matrix[i, j]:.3f}',
                              ha='center', va='center', fontsize=8,
                              color='black' if data_matrix[i, j] < 0.7 else 'white',
                              fontweight='bold')
        
        # Labels
        ax.set_xticks(np.arange(10))
        ax.set_xticklabels(metrics[:10], rotation=45, ha='right', fontsize=9)
        ax.set_yticks(np.arange(len(methods)))
        ax.set_yticklabels(method_names, fontsize=10)
        
        ax.set_title(f'Performance Heatmap - {dataset} Dataset\n(All Methods, Key Metrics)', 
                    fontsize=14, fontweight='bold', pad=20)
        
        # Colorbar
        plt.colorbar(im, ax=ax, label='Normalized Score')
        
        plt.tight_layout()
        
        # Save
        output_path = Path(f'results/heatmap_{dataset}_all_metrics.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"Heatmap for {dataset} saved to: {output_path}")
        
        plt.show()

# ================== MAIN EXECUTION ==================

if __name__ == "__main__":
    print("="*80)
    print("CREATING COMPREHENSIVE VISUALIZATIONS - ALL DATASETS, ALL FEATURES")
    print("="*80)
    print(f"📊 Methods: {', '.join([m.strip() for m in methods])}")
    print(f"📈 Datasets: {', '.join(datasets)}")
    print(f"📝 Metrics: {len(metrics)} features (all displayed)")
    print("="*80)
    
    # Create results directory
    Path('results').mkdir(exist_ok=True)
    
    print("\n🔄 PHASE 1: Creating curved line graphs with ALL datasets...")
    create_curved_line_all_datasets()
    
    print("\n🔄 PHASE 2: Creating method-specific comparisons for ALL datasets...")
    create_method_comparisons_all_datasets()
    
    print("\n🔮 PHASE 3: Creating 3D visualizations with ALL datasets...")
    create_3d_all_datasets_comparison()
    create_3d_bar_all_datasets()
    
    print("\n🔥 PHASE 4: Creating heatmaps for ALL datasets...")
    create_heatmap_all_datasets()
    
    print("\n" + "="*80)
    print("✅ COMPLETED! All visualizations created successfully!")
    print("="*80)
    print("\n📁 Output files saved in 'results/' directory:")
    print("   2D Curved Line Graphs:")
    print("   ├── curved_lines_all_datasets_all_features.png")
    print("   ├── [method]_all_datasets.png (4 files)")
    print("\n   3D Visualizations:")
    print("   ├── 3d_all_datasets_all_features.png")
    print("   ├── 3d_bar_[metric]_all_datasets.png (5 files)")
    print("\n   Heatmaps:")
    print("   ├── heatmap_[dataset]_all_metrics.png (5 files)")
    print("="*80)
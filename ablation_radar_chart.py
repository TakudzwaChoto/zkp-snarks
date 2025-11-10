"""
Create ablation study radar charts showing both 6k and 120k datasets
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path

# Ablation study data for both 6k and 120k datasets
ablation_data = {
    '6k_All_Layers': {
        'ZKP Framework': [0.904, 0.855, 0.973, 0.910, 0.973, 0.855, 0.9, 2378, 2785, 215, 312],
        'Regex Baseline': [0.917, 0.858, 1.000, 0.924, 1.000, 0.858, 0.6, 2380, 2785, 215, 310],
        'LLM Simulator': [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 3.5, 1627, 3000, 0, 1063],
        'Fusion Engine ': [0.917, 0.858, 1.000, 0.924, 1.000, 0.858, 5.6, 2524, 2785, 215, 166],
        'MELON': [0.908, 0.973, 0.839, 0.901, 0.839, 0.973, 0.0, 1627, 3000, 0, 1063],
        'SecurityLingua': [0.899, 0.952, 0.841, 0.893, 0.841, 0.952, 0.0, 1627, 3000, 0, 1063]
    },
    '6k_No_ZKP': {
        'ZKP Framework': [0.500, 0.000, 0.000, 0.000, 0.000, 1.000, 1.0, 0, 3000, 0, 2690],
        'Regex Baseline': [0.917, 0.858, 1.000, 0.924, 1.000, 0.858, 0.5, 2380, 2785, 215, 310],
        'LLM Simulator': [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 3.6, 1627, 3000, 0, 1063],
        'Fusion Engine ': [0.917, 0.858, 1.000, 0.924, 1.000, 0.858, 7.2, 2524, 2785, 215, 166],
        'MELON': [0.908, 0.973, 0.839, 0.901, 0.839, 0.973, 0.0, 1627, 3000, 0, 1063],
        'SecurityLingua': [0.899, 0.952, 0.841, 0.893, 0.841, 0.952, 0.1, 1627, 3000, 0, 1063]
    },
    '6k_No_Regex': {
        'ZKP Framework': [0.904, 0.855, 0.973, 0.910, 0.973, 0.855, 1.9, 2378, 2785, 215, 312],
        'Regex Baseline': [0.500, 0.000, 0.000, 0.000, 0.000, 1.000, 1.0, 0, 3000, 0, 2690],
        'LLM Simulator': [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 6.0, 1627, 3000, 0, 1063],
        'Fusion Engine ': [0.917, 0.858, 1.000, 0.924, 1.000, 0.858, 13.6, 2524, 2785, 215, 166],
        'MELON': [0.908, 0.973, 0.839, 0.901, 0.839, 0.973, 0.0, 1627, 3000, 0, 1063],
        'SecurityLingua': [0.899, 0.952, 0.841, 0.893, 0.841, 0.952, 0.1, 1627, 3000, 0, 1063]
    },
    '120k_All_Layers': {
        'ZKP Framework': [0.907, 0.859, 0.973, 0.913, 0.973, 0.859, 2.0, 47805, 55809, 4191, 6072],
        'Regex Baseline': [0.920, 0.863, 1.000, 0.926, 1.000, 0.863, 0.6, 47534, 55809, 4191, 6343],
        'LLM Simulator': [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 4.5, 32934, 60000, 0, 20943],
        'Fusion Engine ': [0.920, 0.863, 1.000, 0.926, 1.000, 0.863, 6.3, 50670, 55809, 4191, 3207],
        'MELON': [0.906, 0.973, 0.836, 0.899, 0.836, 0.973, 0.0, 32934, 60000, 0, 20943],
        'SecurityLingua': [0.897, 0.950, 0.837, 0.890, 0.837, 0.950, 0.0, 32934, 60000, 0, 20943]
    },
    '120k_No_ZKP': {
        'ZKP Framework': [0.500, 0.000, 0.000, 0.000, 0.000, 1.000, 1.0, 0, 60000, 0, 53877],
        'Regex Baseline': [0.920, 0.863, 1.000, 0.926, 1.000, 0.863, 0.5, 47534, 55809, 4191, 6343],
        'LLM Simulator': [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 4.6, 32934, 60000, 0, 20943],
        'Fusion Engine ': [0.920, 0.863, 1.000, 0.926, 1.000, 0.863, 6.5, 50670, 55809, 4191, 3207],
        'MELON': [0.906, 0.973, 0.836, 0.899, 0.836, 0.973, 0.0, 32934, 60000, 0, 20943],
        'SecurityLingua': [0.897, 0.950, 0.837, 0.890, 0.837, 0.950, 0.0, 32934, 60000, 0, 20943]
    },
    '120k_No_Regex': {
        'ZKP Framework': [0.907, 0.859, 0.973, 0.913, 0.973, 0.859, 0.6, 47805, 55809, 4191, 6072],
        'Regex Baseline': [0.500, 0.000, 0.000, 0.000, 0.000, 1.000, 1.0, 0, 60000, 0, 53877],
        'LLM Simulator': [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 4.7, 32934, 60000, 0, 20943],
        'Fusion Engine ': [0.920, 0.863, 1.000, 0.926, 1.000, 0.863, 5.5, 50670, 55809, 4191, 3207],
        'MELON': [0.906, 0.973, 0.836, 0.899, 0.836, 0.973, 0.1, 32934, 60000, 0, 20943],
        'SecurityLingua': [0.897, 0.950, 0.837, 0.890, 0.837, 0.950, 0.0, 32934, 60000, 0, 20943]
    }
}

# All 11 features
metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Sensitivity', 'Specificity', 
           'Latency (ms)', 'TP', 'TN', 'FP', 'FN']

methods = ['ZKP Framework', 'Regex Baseline', 'LLM Simulator', 'Fusion Engine ', 'MELON', 'SecurityLingua']

# Beautiful color palettes for different datasets
color_palettes = {
    '6k': ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'],  # Vibrant colors for 6k
    '120k': ['#264653', '#2A9D8F', '#E9C46A', '#F4A261', '#E76F51', '#8AC926']  # Muted colors for 120k
}

line_styles = {
    '6k': '-',      # Solid lines for 6k
    '120k': '--'    # Dashed lines for 120k
}

markers = {
    '6k': 'o',      # Circles for 6k
    '120k': 's'     # Squares for 120k
}

def normalize_values(original_values, dataset_size):
    """Normalize values to 0-1 scale for radar chart"""
    normalized = []
    
    for i, value in enumerate(original_values):
        if i < 6:  # Performance metrics (0-1 scale)
            normalized.append(value)
        elif i == 6:  # Latency (reverse: lower is better)
            normalized.append(max(0, 1 - (value / 15)))  # 0ms = 1.0, 15ms = 0.0
        else:  # Count metrics (TP, TN, FP, FN)
            if i in [7, 8]:  # TP, TN (higher better)
                normalized.append(value / dataset_size)
            else:  # FP, FN (lower better - reverse scale)
                normalized.append(max(0, 1 - (value / (dataset_size * 0.5))))
    
    return normalized

def create_ablation_radar_both_datasets():
    """Create radar chart showing both 6k and 120k datasets for ablation study"""
    
    plt.style.use('default')
    sns.set_theme(style="white")
    
    # Create figure
    fig = plt.figure(figsize=(16, 10))
    ax = fig.add_subplot(111, polar=True)
    
    # Prepare radar chart angles
    angles = np.linspace(0, 2*np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]  # Complete the circle
    
    # Focus on Ensemble method across configurations for both datasets
    configs_6k = ['6k_All_Layers', '6k_No_ZKP', '6k_No_Regex']
    configs_120k = ['120k_All_Layers', '120k_No_ZKP', '120k_No_Regex']
    
    config_names_6k = ['All Layers (6k)', 'No ZKP (6k)', 'No Regex (6k)']
    config_names_120k = ['All Layers (120k)', 'No ZKP (120k)', 'No Regex (120k)']
    
    # Plot 6k dataset configurations
    for i, config in enumerate(configs_6k):
        values = normalize_values(ablation_data[config]['Fusion Engine '], 6000)
        values = values + [values[0]]  # Complete the circle
        
        color = color_palettes['6k'][i % len(color_palettes['6k'])]
        ax.plot(angles, values, 
                linestyle=line_styles['6k'], 
                marker=markers['6k'], 
                linewidth=3, markersize=8, 
                label=config_names_6k[i], 
                color=color, alpha=0.9)
        ax.fill(angles, values, alpha=0.15, color=color)
    
    # Plot 120k dataset configurations
    for i, config in enumerate(configs_120k):
        values = normalize_values(ablation_data[config]['Fusion Engine '], 120000)
        values = values + [values[0]]  # Complete the circle
        
        color = color_palettes['120k'][i % len(color_palettes['120k'])]
        ax.plot(angles, values, 
                linestyle=line_styles['120k'], 
                marker=markers['120k'], 
                linewidth=3, markersize=8, 
                label=config_names_120k[i], 
                color=color, alpha=0.9)
        ax.fill(angles, values, alpha=0.15, color=color)
    
    # Configure radar chart
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=11, fontweight='bold')
    ax.set_ylim(0, 1.0)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=9)
    ax.grid(True, alpha=0.3)
    
    # Enhanced legend showing dataset distinction
    legend = ax.legend(loc='upper right', bbox_to_anchor=(1.4, 1.0), 
                      frameon=True, fancybox=True, shadow=True, 
                      fontsize=11, ncol=1)
    legend.get_frame().set_facecolor('#f8f9fa')
    legend.get_frame().set_alpha(0.9)
    
    # Title clearly indicating both datasets
    plt.title('', fontsize=16, fontweight='bold', pad=40, color='#2c3e50')
    
    # Add dataset annotation
    ax.annotate('○ = 6k Dataset\n□ = 120k Dataset', 
               xy=(0.02, 0.98), xycoords='axes fraction',
               fontsize=10, color='#7f8c8d', fontweight='bold',
               bbox=dict(boxstyle="round,pad=0.3", facecolor='#ecf0f1', alpha=0.8))
    
    plt.tight_layout()
    
    output_path = Path('results/ablation_radar_both_datasets.png')
    output_path.parent.mkdir(exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Ablation radar with both datasets saved to: {output_path}")
    
    plt.show()

def create_comparison_radar_methods_both_datasets():
    """Compare all methods in All Layers configuration for both datasets"""
    
    plt.style.use('default')
    sns.set_theme(style="white")
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 8), subplot_kw=dict(projection='polar'))
    
    # Prepare radar chart angles
    angles = np.linspace(0, 2*np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]
    
    # Plot 6k dataset (left)
    for i, method in enumerate(methods):
        values = normalize_values(ablation_data['6k_All_Layers'][method], 6000)
        values = values + [values[0]]
        
        color = color_palettes['6k'][i % len(color_palettes['6k'])]
        ax1.plot(angles, values, 'o-', linewidth=2.5, markersize=6, 
                label=method, color=color, alpha=0.8)
        ax1.fill(angles, values, alpha=0.1, color=color)
    
    # Plot 120k dataset (right)
    for i, method in enumerate(methods):
        values = normalize_values(ablation_data['120k_All_Layers'][method], 120000)
        values = values + [values[0]]
        
        color = color_palettes['120k'][i % len(color_palettes['120k'])]
        ax2.plot(angles, values, 's-', linewidth=2.5, markersize=6, 
                label=method, color=color, alpha=0.8)
        ax2.fill(angles, values, alpha=0.1, color=color)
    
    # Configure both radar charts
    for ax, title in zip([ax1, ax2], ['6k Dataset - All Layers', '120k Dataset - All Layers']):
        ax.set_theta_offset(np.pi / 2)
        ax.set_theta_direction(-1)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(metrics, fontsize=10, fontweight='bold')
        ax.set_ylim(0, 1.0)
        ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
        ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=8)
        ax.grid(True, alpha=0.3)
        ax.set_title(title, fontsize=14, fontweight='bold', pad=30)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=9)
    
    plt.suptitle('', fontsize=16, fontweight='bold', y=0.95)
    plt.tight_layout()
    
    output_path = Path('results/methods_comparison_both_datasets.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Methods comparison both datasets saved to: {output_path}")
    
    plt.show()

def create_scalability_radar():
    """Show scalability by comparing same configuration across datasets"""
    
    plt.style.use('default')
    sns.set_theme(style="white")
    
    fig, axes = plt.subplots(2, 2, figsize=(18, 12), subplot_kw=dict(projection='polar'))
    axes = axes.flatten()
    
    # Key configurations to compare
    config_pairs = [
        ('6k_All_Layers', '120k_All_Layers', 'All Layers'),
        ('6k_No_ZKP', '120k_No_ZKP', 'No ZKP'),
        ('6k_No_Regex', '120k_No_Regex', 'No Regex'),
        ('6k_All_Layers', '120k_All_Layers', 'Fusion Engine Only')  # Focus on Fusion Engine 
    ]
    
    angles = np.linspace(0, 2*np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]
    
    for idx, (config_6k, config_120k, title) in enumerate(config_pairs):
        if idx >= len(axes):
            break
            
        ax = axes[idx]
        
        # Method to focus on (Ensemble for most, all for first)
        if idx == 0:  # First plot shows all methods
            methods_to_plot = methods
        else:  # Other plots focus on Ensemble
            methods_to_plot = ['Fusion Engine ']
        
        for method in methods_to_plot:
            # 6k dataset
            if method in ablation_data[config_6k]:
                values_6k = normalize_values(ablation_data[config_6k][method], 6000)
                values_6k = values_6k + [values_6k[0]]
                ax.plot(angles, values_6k, 'o-', linewidth=2, markersize=4, 
                       label=f'{method} (6k)', alpha=0.7)
            
            # 120k dataset
            if method in ablation_data[config_120k]:
                values_120k = normalize_values(ablation_data[config_120k][method], 120000)
                values_120k = values_120k + [values_120k[0]]
                ax.plot(angles, values_120k, 's--', linewidth=2, markersize=4, 
                       label=f'{method} (120k)', alpha=0.7)
        
        ax.set_theta_offset(np.pi / 2)
        ax.set_theta_direction(-1)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(metrics, fontsize=8)
        ax.set_ylim(0, 1.0)
        ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
        ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=6)
        ax.grid(True, alpha=0.3)
        ax.set_title(f'{title}\n6k vs 120k', fontsize=11, fontweight='bold', pad=20)
        ax.legend(loc='upper right', bbox_to_anchor=(1.4, 1.0), fontsize=7)
    
    plt.suptitle('', fontsize=16, fontweight='bold', y=0.95)
    plt.tight_layout()
    
    output_path = Path('results/scalability_radar.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Scalability radar saved to: {output_path}")
    
    plt.show()

def create_dataset_legend():
    """Create a separate legend explaining the dataset visual coding"""
    
    fig, ax = plt.subplots(figsize=(8, 2))
    ax.axis('off')
    
    # Create custom legend entries
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#FF6B6B', 
                  markersize=10, label='6k Dataset (Solid lines)'),
        plt.Line2D([0], [0], marker='s', color='w', markerfacecolor='#264653', 
                  markersize=10, label='120k Dataset (Dashed lines)'),
        plt.Line2D([0], [0], color='#FF6B6B', linestyle='-', linewidth=3, 
                  label='6k - Vibrant Colors'),
        plt.Line2D([0], [0], color='#264653', linestyle='--', linewidth=3, 
                  label='120k - Muted Colors')
    ]
    
    ax.legend(handles=legend_elements, loc='center', frameon=True, 
             fancybox=True, shadow=True, fontsize=12, ncol=2)
    
    ax.set_title('Dataset Visual Coding Legend', fontsize=14, fontweight='bold', pad=20)
    
    output_path = Path('results/dataset_legend.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Dataset legend saved to: {output_path}")
    
    plt.show()

if __name__ == "__main__":
    print("Creating ablation radar charts with both 6k and 120k datasets...")
    
    create_dataset_legend()
    create_ablation_radar_both_datasets()
    create_comparison_radar_methods_both_datasets()
    create_scalability_radar()
    
    print("✅ Done! All radar charts created showing both datasets clearly.")
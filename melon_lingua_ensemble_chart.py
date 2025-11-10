"""
Create comparative performance chart for Ensemble (Our Model), MELON, and SecurityLingua
across F1-score, precision, recall, and accuracy with beautiful Seaborn styling.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path

# Data from the ablation results (All_Layers configuration)
data = {
    'Method': ['Fusion Engine ', 'MELON', 'SecurityLingua'] * 2,
    'Dataset': ['120k'] * 3 + ['6k'] * 3,
    'F1-Score': [0.9262, 0.8991, 0.8902, 0.9236, 0.9012, 0.8931],
    'Precision': [0.8626, 0.9725, 0.9505, 0.8581, 0.9730, 0.9524],
    'Recall': [1.0000, 0.8360, 0.8371, 1.0000, 0.8393, 0.8407],
    'Accuracy': [0.9203, 0.9062, 0.8967, 0.9173, 0.9080, 0.8993]
}

def setup_seaborn_style():
    """Configure beautiful Seaborn styling for publication-quality figures"""
    sns.set_theme(style="whitegrid")
    
    # Custom color palette - Ensemble (ours) in distinctive color
    palette = ["#2E86AB", "#A23B72", "#F18F01"]
    
    # Set custom style parameters
    plt.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['Times New Roman'],
        'font.size': 12,
        'axes.labelsize': 14,
        'axes.titlesize': 14,
        'axes.titleweight': 'bold',
        'xtick.labelsize': 12,
        'ytick.labelsize': 12,
        'legend.fontsize': 11,
        'figure.titlesize': 16,
        'figure.titleweight': 'bold',
        'grid.alpha': 0.3,
        'grid.linestyle': '--',
        'axes.linewidth': 1.2,
        'lines.linewidth': 2.5
    })
    
    return palette

def create_comparison_chart():
    """Create a comprehensive comparison chart with beautiful Seaborn styling"""
    
    palette = setup_seaborn_style()
    
    # Create figure with subplots
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Convert data to DataFrame for easier Seaborn handling
    df = pd.DataFrame(data)
    
    # Melt the dataframe for easier plotting
    df_melted = df.melt(id_vars=['Method', 'Dataset'], 
                        value_vars=['F1-Score', 'Precision', 'Recall', 'Accuracy'],
                        var_name='Metric', value_name='Score')
    
    # Create individual subplots for each metric
    metrics = ['F1-Score', 'Precision', 'Recall', 'Accuracy']
    
    for idx, metric in enumerate(metrics):
        ax = axes[idx // 2, idx % 2]
        
        # Filter data for current metric
        metric_data = df_melted[df_melted['Metric'] == metric]
        
        # Create grouped bar plot using Seaborn
        sns.barplot(data=metric_data, x='Method', y='Score', hue='Dataset', 
                   ax=ax, palette=palette[:2], saturation=0.85,
                   edgecolor='black', linewidth=1.2, alpha=0.9)
        
        # Customize the plot
        ax.set_ylabel(metric, fontsize=14, fontweight='bold')
        ax.set_xlabel('Method', fontsize=14, fontweight='bold')
        ax.set_ylim(0.8, 1.02)
        
        # Add value annotations on bars
        for container in ax.containers:
            ax.bar_label(container, fmt='%.3f', padding=3, fontsize=10, 
                        fontweight='bold', color='black')
        
        # Customize legend
        ax.legend(loc='lower right', frameon=True, fancybox=True, 
                 shadow=True, framealpha=0.9, edgecolor='black')
        
        # Improve grid and spines
        ax.grid(True, alpha=0.2, axis='y')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_linewidth(1.2)
        ax.spines['bottom'].set_linewidth(1.2)
        
        # Rotate x-axis labels for better readability
        ax.tick_params(axis='x', rotation=0)

    # Adjust layout
    plt.tight_layout()
    plt.subplots_adjust(hspace=0.3, wspace=0.25)
    
    # Save the plot
    output_path = Path('results/comparative_performance_chart.png')
    output_path.parent.mkdir(exist_ok=True)
    plt.savefig(output_path, dpi=350, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    print(f"Chart saved to: {output_path}")
    
    # Also save as PDF for publication
    pdf_path = Path('results/comparative_performance_chart.pdf')
    plt.savefig(pdf_path, bbox_inches='tight', facecolor='white')
    print(f"PDF saved to: {pdf_path}")
    
    plt.show()

def create_radar_chart():
    """Create a radar chart for comprehensive method comparison using 120k dataset"""
    
    palette = setup_seaborn_style()
    
    # Prepare data for radar chart - using 120k dataset
    metrics = ['F1-Score', 'Precision', 'Recall', 'Accuracy']
    methods = ['Fusion Engine ', 'MELON', 'SecurityLingua']
    
    # Use 120k dataset for radar chart (first 3 entries)
    radar_data = []
    for i, method in enumerate(methods):
        values = [data[metric][i] for metric in metrics]
        radar_data.append(values)
    
    # Create radar chart
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, polar=True)
    
    # Compute angles for radar chart
    angles = np.linspace(0, 2*np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]  # Complete the circle
    
    # Plot each method
    for i, method in enumerate(methods):
        values = radar_data[i] + [radar_data[i][0]]  # Complete the circle
        ax.plot(angles, values, 'o-', linewidth=3, markersize=8, 
               label=method, color=palette[i])
        ax.fill(angles, values, alpha=0.25, color=palette[i])
    
    # Customize radar chart
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=13, fontweight='bold')
    ax.set_ylim(0.8, 1.0)
    ax.set_yticks([0.8, 0.85, 0.9, 0.95, 1.0])
    ax.set_yticklabels(['0.80', '0.85', '0.90', '0.95', '1.00'], 
                      fontsize=11, color='gray')
    ax.grid(True, alpha=0.3)
    
    plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), 
              frameon=True, fancybox=True, shadow=True)
    
    # Save radar chart
    radar_path = Path('results/radar_comparison.png')
    plt.savefig(radar_path, dpi=350, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    print(f"Radar chart saved to: {radar_path}")
    
    plt.show()

def create_performance_table():
    """Create a beautiful styled performance table"""
    
    # Create summary DataFrame
    summary_data = {
        'Method': ['Fusion Engine ', 'MELON', 'SecurityLingua'],
        'F1-Score (120k)': [f"{data['F1-Score'][i]:.4f}" for i in range(3)],
        'F1-Score (6k)': [f"{data['F1-Score'][i+3]:.4f}" for i in range(3)],
        'Precision (120k)': [f"{data['Precision'][i]:.4f}" for i in range(3)],
        'Precision (6k)': [f"{data['Precision'][i+3]:.4f}" for i in range(3)],
        'Recall (120k)': [f"{data['Recall'][i]:.4f}" for i in range(3)],
        'Recall (6k)': [f"{data['Recall'][i+3]:.4f}" for i in range(3)],
        'Accuracy (120k)': [f"{data['Accuracy'][i]:.4f}" for i in range(3)],
        'Accuracy (6k)': [f"{data['Accuracy'][i+3]:.4f}" for i in range(3)]
    }
    
    df = pd.DataFrame(summary_data)
    
    # Create styled table
    styled_df = df.style\
        .set_properties(**{
            'background-color': 'white',
            'border-color': 'black',
            'border-width': '1px',
            'border-style': 'solid',
            'font-size': '12pt'
        })\
        .set_table_styles([
            {'selector': 'th', 'props': [('background-color', '#2E86AB'), 
                                       ('color', 'white'),
                                       ('font-weight', 'bold'),
                                       ('border', '1px solid black')]},
            {'selector': 'td', 'props': [('border', '1px solid black')]},
            {'selector': 'tr:nth-child(even)', 'props': [('background-color', '#f8f9fa')]},
            {'selector': 'tr:nth-child(odd)', 'props': [('background-color', 'white')]}
        ])\
        .format(precision=4)
    
    # Save as CSV
    csv_path = Path('results/comparative_performance_table.csv')
    df.to_csv(csv_path, index=False)
    print(f"Summary table saved to: {csv_path}")
    
    # Save as styled HTML
    html_path = Path('results/comparative_performance_table.html')
    with open(html_path, 'w') as f:
        f.write(styled_df.to_html())
    print(f"Styled HTML table saved to: {html_path}")
    
    print("\n" + "="*80)
    print("COMPARATIVE PERFORMANCE SUMMARY")
    print("="*80)
    print(df.to_string(index=False, justify='center'))
    print("="*80)
    
    return df

if __name__ == "__main__":
    print("Creating comprehensive comparative performance analysis...")
    
    # Create all visualizations
    create_comparison_chart()
    create_radar_chart()
    create_performance_table()
    
    print("\n✅ All visualizations completed successfully!")
    print("📊 Comparative bar charts created")
    print("🎯 Radar chart generated")
    print("📋 Performance tables saved")
    print("\nResults saved to 'results/' directory")
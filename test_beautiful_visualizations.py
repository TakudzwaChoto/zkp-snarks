#!/usr/bin/env python3
"""
Test script to demonstrate beautiful visualizations
Shows enhanced bar charts, pie charts, line charts, and heatmaps with beautiful colors
"""

import os
import sys

try:
    import matplotlib
    matplotlib.use('Agg')  # Set backend for headless environments
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import seaborn as sns
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
    import pandas as pd
except ImportError as e:
    print(f"Required packages not available: {e}")
    print("Please install: pip install matplotlib seaborn numpy pandas")
    print("Or run: pip3 install --user matplotlib seaborn numpy pandas")
    sys.exit(1)

class BeautifulVisualizationDemo:
    """Demonstration of beautiful visualizations with enhanced styling"""
    
    # Beautiful color palettes for different chart types
    BAR_COLORS = {
        'performance': ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'],
        'metrics': ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe'],
        'latency': ['#a8edea', '#fed6e3', '#ffecd2', '#fcb69f', '#ff9a9e', '#fecfef']
    }
    
    PIE_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#FF8A80', '#82B1FF']
    
    LINE_COLORS = ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#43e97b', '#38f9d7']
    
    HEATMAP_CMAP = 'RdYlBu_r'  # Red-Yellow-Blue reversed for better contrast
    
    def __init__(self):
        self.setup_modern_style()
        
    def setup_modern_style(self):
        """Set up modern matplotlib styling with beautiful aesthetics"""
        # Set modern style
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
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10
        plt.rcParams['legend.fontsize'] = 10
        plt.rcParams['figure.titlesize'] = 16

    def create_sample_data(self):
        """Create sample data for demonstration"""
        return {
            'metrics': {
                'ZKP Framework': {
                    'accuracy': 0.95,
                    'precision': 0.92,
                    'recall': 0.89,
                    'f1': 0.90
                },
                'Regex Baseline': {
                    'accuracy': 0.78,
                    'precision': 0.75,
                    'recall': 0.82,
                    'f1': 0.78
                },
                'Semantic Classifier': {
                    'accuracy': 0.87,
                    'precision': 0.85,
                    'recall': 0.88,
                    'f1': 0.86
                },
                'Transformer Model': {
                    'accuracy': 0.91,
                    'precision': 0.89,
                    'recall': 0.93,
                    'f1': 0.91
                }
            },
            'latency': {
                'ZKP Framework': 45.2,
                'Regex Baseline': 12.8,
                'Semantic Classifier': 156.7,
                'Transformer Model': 234.1
            },
            'confusion_matrix': {
                'y_true': [0, 0, 1, 1, 0, 1, 0, 1, 1, 0] * 10,
                'y_pred': [0, 0, 1, 1, 0, 1, 0, 1, 1, 0] * 10,
                'labels': ['Safe', 'Adversarial']
            }
        }

    def demo_enhanced_bar_charts(self, data, output_dir):
        """Demonstrate enhanced bar charts with beautiful colors"""
        print("🎨 Creating enhanced bar charts...")
        
        # 1. Performance Metrics Comparison
        methods = list(data['metrics'].keys())
        metrics_list = ['accuracy', 'precision', 'recall', 'f1']
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Performance Metrics Comparison - Enhanced Styling', 
                    fontsize=18, fontweight='bold', color='#2c3e50', y=0.95)
        
        colors = self.BAR_COLORS['metrics']
        
        for i, metric in enumerate(metrics_list):
            ax = axes[i // 2, i % 2]
            values = [data['metrics'][m][metric] for m in methods]
            
            bars = ax.bar(methods, values, color=colors[i], alpha=0.8, 
                         edgecolor='white', linewidth=2)
            
            ax.set_title(f'{metric.title()} Comparison', fontweight='bold', color='#2c3e50')
            ax.set_ylabel(f'{metric.title()} Score', fontweight='bold')
            ax.set_xticklabels(methods, rotation=45, ha='right')
            ax.grid(True, alpha=0.3, linestyle='--')
            ax.set_ylim(0, 1.1)
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height + 0.02,
                       f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'enhanced_bar_charts.png'), 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        print("✅ Enhanced bar charts created!")

    def demo_beautiful_pie_chart(self, data, output_dir):
        """Demonstrate beautiful pie chart with enhanced styling"""
        print("🥧 Creating beautiful pie chart...")
        
        # Calculate average performance for each method
        method_scores = {}
        for method, metrics in data['metrics'].items():
            avg_score = sum(metrics.values()) / len(metrics)
            method_scores[method] = avg_score
        
        # Sort by performance
        sorted_methods = sorted(method_scores.items(), key=lambda x: x[1], reverse=True)
        methods, scores = zip(*sorted_methods)
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Use custom colors
        colors = self.PIE_COLORS[:len(methods)]
        
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
        
        ax.set_title('Method Performance Distribution - Beautiful Styling', 
                    fontsize=16, fontweight='bold', color='#2c3e50', pad=20)
        
        # Add legend
        legend_elements = [mpatches.Patch(color=color, label=f'{method}: {score:.3f}')
                         for method, score, color in zip(methods, scores, colors)]
        ax.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0, 0.5, 1))
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'beautiful_pie_chart.png'), 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        print("✅ Beautiful pie chart created!")

    def demo_line_chart_trends(self, data, output_dir):
        """Demonstrate line chart with performance trends"""
        print("📈 Creating line chart with trends...")
        
        methods = list(data['metrics'].keys())
        metrics_list = ['accuracy', 'precision', 'recall', 'f1']
        
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Use custom line colors
        colors = self.LINE_COLORS[:len(metrics_list)]
        
        # Plot each metric as a line
        for i, metric in enumerate(metrics_list):
            values = [data['metrics'][method][metric] for method in methods]
            ax.plot(methods, values, marker='o', linewidth=3, markersize=10,
                   color=colors[i], label=metric.title(), alpha=0.8)
        
        ax.set_title('Performance Trends Across Methods - Enhanced Styling', 
                    fontsize=16, fontweight='bold', color='#2c3e50', pad=20)
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
                value = data['metrics'][method][metric]
                ax.annotate(f'{value:.3f}', 
                           (method_idx, value),
                           textcoords="offset points",
                           xytext=(0, 10),
                           ha='center',
                           fontsize=9,
                           fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'line_chart_trends.png'), 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        print("✅ Line chart with trends created!")

    def demo_enhanced_heatmap(self, data, output_dir):
        """Demonstrate enhanced heatmap with beautiful colors"""
        print("🔥 Creating enhanced heatmap...")
        
        # Create sample confusion matrix data
        cm_data = np.array([
            [85, 15],
            [12, 88]
        ])
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Use a beautiful diverging colormap
        sns.heatmap(cm_data, annot=True, fmt='d', cmap='RdYlBu_r', ax=ax,
                   cbar_kws={'label': 'Count'}, linewidths=0.5, linecolor='white')
        
        ax.set_title('Enhanced Confusion Matrix - Beautiful Styling', 
                    fontsize=16, fontweight='bold', color='#2c3e50', pad=20)
        ax.set_xlabel('Predicted', fontweight='bold', fontsize=12)
        ax.set_ylabel('Actual', fontweight='bold', fontsize=12)
        
        # Set custom labels
        ax.set_xticklabels(['Safe', 'Adversarial'])
        ax.set_yticklabels(['Safe', 'Adversarial'])
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'enhanced_heatmap.png'), 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        print("✅ Enhanced heatmap created!")

    def demo_latency_comparison(self, data, output_dir):
        """Demonstrate enhanced latency comparison chart"""
        print("⚡ Creating latency comparison chart...")
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Use custom colors for latency bars
        colors = self.BAR_COLORS['latency']
        methods = list(data['latency'].keys())
        values = list(data['latency'].values())
        
        # Create gradient effect by varying alpha
        bars = ax.bar(methods, values, color=colors[:len(methods)], 
                     alpha=0.8, edgecolor='white', linewidth=2)
        
        ax.set_title('Latency Comparison - Enhanced Styling', fontsize=16, fontweight='bold', 
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
        plt.savefig(os.path.join(output_dir, 'latency_comparison.png'), 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        print("✅ Latency comparison chart created!")

    def run_all_demos(self):
        """Run all visualization demonstrations"""
        print("🚀 Starting Beautiful Visualization Demonstrations")
        print("=" * 60)
        
        # Create output directory
        output_dir = "beautiful_visualizations_demo"
        os.makedirs(output_dir, exist_ok=True)
        
        # Create sample data
        data = self.create_sample_data()
        
        # Run all demonstrations
        try:
            self.demo_enhanced_bar_charts(data, output_dir)
            self.demo_beautiful_pie_chart(data, output_dir)
            self.demo_line_chart_trends(data, output_dir)
            self.demo_enhanced_heatmap(data, output_dir)
            self.demo_latency_comparison(data, output_dir)
            
            print("\n🎉 All visualizations created successfully!")
            print(f"📁 Check the '{output_dir}' directory for the generated charts:")
            print("   • enhanced_bar_charts.png - Beautiful bar charts with different colors")
            print("   • beautiful_pie_chart.png - Enhanced pie chart with custom colors")
            print("   • line_chart_trends.png - Line chart showing performance trends")
            print("   • enhanced_heatmap.png - Beautiful heatmap with custom colormap")
            print("   • latency_comparison.png - Enhanced latency comparison")
            
        except Exception as e:
            print(f"❌ Error during visualization creation: {e}")
            import traceback
            traceback.print_exc()

def main():
    """Main function to run the demonstration"""
    demo = BeautifulVisualizationDemo()
    demo.run_all_demos()

if __name__ == "__main__":
    main()
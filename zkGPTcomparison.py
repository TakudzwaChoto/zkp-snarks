import matplotlib.pyplot as plt
from scipy.interpolate import CubicSpline
from mpl_toolkits.mplot3d import Axes3D
import pandas as pd
import numpy as np
import matplotlib.font_manager as fm
import os
from math import pi

# ================== SMART FONT CONFIGURATION ==================

def get_best_font():
    """Find the best available sans-serif font on the system."""
    # Priority list of clean sans-serif fonts
    preferred_fonts = ['Helvetica', 'Arial', 'DejaVu Sans', 'Liberation Sans', 
                      'Bitstream Vera Sans', 'sans-serif']
    
    try:
        # Get list of available fonts
        available_fonts = [f.name for f in fm.fontManager.ttflist]
        
        # Find first available preferred font
        for font in preferred_fonts:
            if font in available_fonts or font == 'sans-serif':
                return font
    except Exception as e:
        print(f"Warning: Font detection failed ({e}), using sans-serif fallback")
    
    return 'sans-serif'  # Ultimate fallback

# Get the best font for your system
BEST_FONT = get_best_font()
print(f"Using font: {BEST_FONT}")

plt.rcParams.update({
    # Typography - using the best available font
    'font.family': BEST_FONT,
    'font.weight': 300,  # Light weight
    'axes.labelweight': 300,
    'axes.titleweight': 300,
    
    # Sizes
    'axes.labelsize': 8,
    'axes.titlesize': 9,
    'xtick.labelsize': 7,
    'ytick.labelsize': 7,
    'legend.fontsize': 7,
    
    # Lines and frames
    'axes.linewidth': 0.5,
    'xtick.major.width': 0.5,
    'ytick.major.width': 0.5,
    'axes.edgecolor': '#333333',
    'xtick.color': '#333333',
    'ytick.color': '#333333',
    
    # Grid (subtle)
    'axes.grid': True,
    'grid.alpha': 0.2,
    'grid.linestyle': '-',
    'grid.linewidth': 0.3,
    
    # Figure - disable constrained_layout to avoid warnings
    'figure.constrained_layout.use': False,
    'figure.autolayout': True,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
})

# Sophisticated color palette
COLORS = {
    'zkGPT': '#4870A5',     # Deeper blue
    'our_work': '#C45E3A',   # Terracotta
    'improvement': '#3F7E6B' # Sage green
}

# ================== DATA ==================

data = {
    "Metric": [
        "Proof Generation Time (s)",
        "Proof Verification Time (ms)", 
        "Proof Size (KB)",
        "Field Multiplications (M)",
        "Lookup Operations (K)",
        "Memory Usage (MB)",
        "Throughput (KRPM)"
    ],
    "zkGPT": [21.8, 350, 101, 15.2, 2.8, 8.2, 2.75],
    "Our Work": [0.84, 0.24, 0.192, 0.042, 0.003, 0.016, 1019.4],
    "Improvement": [26, 1458, 526, 362, 933, 512, 370]
}

df = pd.DataFrame(data)

# ================== FIGURE 1: ELEGANT 3D COMPARISON ==================

def create_elegant_comparison():
    """Create an elegant 3D comparison with better visual hierarchy."""
    # Increased figure size significantly to avoid layout collapse
    fig = plt.figure(figsize=(16, 8))
    
    # Create subplots with better spacing
    gs = fig.add_gridspec(1, 2, width_ratios=[1.2, 1], wspace=0.3)
    
    # === LEFT: Side-by-side comparison ===
    ax1 = fig.add_subplot(gs[0], projection='3d')
    
    x = np.arange(len(df))
    width = 0.35
    
    # Use log scale for better visualization
    zk_h = np.log10(df["zkGPT"] + 0.1)
    our_h = np.log10(df["Our Work"] + 0.1)
    
    # Plot bars with subtle gradients
    for i in range(len(df)):
        # zkGPT bars
        ax1.bar3d(i-width/2, 0, 0, width, 0.2, zk_h[i], 
                 color=COLORS['zkGPT'], alpha=0.85, 
                 edgecolor='white', linewidth=0.3, shade=True)
        
        # Our Work bars
        ax1.bar3d(i+width/2, 0, 0, width, 0.2, our_h[i],
                 color=COLORS['our_work'], alpha=0.85,
                 edgecolor='white', linewidth=0.3, shade=True)
    
    # Styling
    ax1.view_init(elev=25, azim=35)
    ax1.set_xticks(x)
    ax1.set_xticklabels(df['Metric'], fontsize=7, rotation=25, ha='right')
    ax1.set_yticks([])
    ax1.set_zlabel('log10(value)', fontsize=8, labelpad=8)
    ax1.set_title('zkGPT vs Our Work\n(log scale)', fontsize=10, pad=15, weight=300)
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS['zkGPT'], alpha=0.85, label='zkGPT'),
        Patch(facecolor=COLORS['our_work'], alpha=0.85, label='Our Work')
    ]
    ax1.legend(handles=legend_elements, loc='upper left', 
               frameon=True, fancybox=False, edgecolor='#DDDDDD', facecolor='white')
    
    # === RIGHT: Improvement visualization ===
    ax2 = fig.add_subplot(gs[1])
    
    imp = df["Improvement"]
    y_pos = np.arange(len(imp))
    
    # Horizontal bars for improvement
    bars = ax2.barh(y_pos, imp, color=COLORS['improvement'], 
                    alpha=0.8, height=0.6)
    
    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, imp)):
        if val > 200:
            ax2.text(val + 20, bar.get_y() + bar.get_height()/2, 
                    f'{val:.0f}×', va='center', ha='left', fontsize=8, weight=300)
        else:
            ax2.text(val - 20, bar.get_y() + bar.get_height()/2, 
                    f'{val:.0f}×', va='center', ha='right', fontsize=8, weight=300)
    
    # Styling
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(df['Metric'], fontsize=7)
    ax2.set_xlabel('Improvement Factor (×)', fontsize=8)
    ax2.set_title('Performance Improvement', fontsize=10, pad=15, weight=300)
    
    # Add subtle vertical lines for reference
    ax2.axvline(x=100, color='#CCCCCC', linestyle='--', linewidth=0.5, alpha=0.5)
    ax2.axvline(x=500, color='#CCCCCC', linestyle='--', linewidth=0.5, alpha=0.5)
    
    # Invert y-axis for better readability
    ax2.invert_yaxis()
    
    # Adjust layout manually
    plt.tight_layout()
    
    return fig

# ================== FIGURE 2: DETAILED RADAR CHART ==================

def create_radar_comparison():
    """Create a radar chart for multi-dimensional comparison."""
    fig = plt.figure(figsize=(12, 10))
    ax = fig.add_subplot(111, projection='polar')
    
    # Prepare data (normalize for radar)
    categories = df['Metric'].tolist()
    N = len(categories)
    angles = [n / float(N) * 2 * pi for n in range(N)]
    angles += angles[:1]  # Close the loop
    
    # Normalize values for radar (0-1 scale)
    zk_norm = np.array(df['zkGPT']) / max(df['zkGPT'])
    our_norm = np.array(df['Our Work']) / max(df['Our Work'])
    
    # Add first value to end to close the loop
    zk_vals = np.append(zk_norm, zk_norm[0])
    our_vals = np.append(our_norm, our_norm[0])
    
    # Plot
    ax.plot(angles, zk_vals, 'o-', linewidth=1.5, color=COLORS['zkGPT'], 
            label='zkGPT', alpha=0.8)
    ax.fill(angles, zk_vals, color=COLORS['zkGPT'], alpha=0.1)
    
    ax.plot(angles, our_vals, 'o-', linewidth=1.5, color=COLORS['our_work'], 
            label='Our Work', alpha=0.8)
    ax.fill(angles, our_vals, color=COLORS['our_work'], alpha=0.1)
    
    # Styling - rotate so first category is at top
    ax.set_theta_offset(pi / 2)
    ax.set_theta_direction(-1)
    
    # Set category labels
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=8, weight=300)
    ax.set_yticklabels([])
    ax.set_ylim(0, 1)
    
    # Add circular grid
    ax.grid(True, alpha=0.2)
    
    # Legend
    ax.legend(loc='upper right', bbox_to_anchor=(1.1, 1.1), 
              frameon=True, fancybox=False, edgecolor='#DDDDDD')
    
    ax.set_title('Multi-Dimensional Comparison\n(normalized)', 
                fontsize=12, pad=20, weight=300)
    
    plt.tight_layout()
    return fig

# ================== FIGURE 3: SUMMARY TABLE (Optional) ==================

def create_summary_table():
    """Create a styled table with the exact numbers."""
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare data for table
    table_data = []
    for i, row in df.iterrows():
        table_data.append([
            row['Metric'],
            f"{row['zkGPT']:.3f}",
            f"{row['Our Work']:.3f}",
            f"{row['Improvement']}×"
        ])
    
    # Create table
    table = ax.table(
        cellText=table_data,
        colLabels=['Metric', 'zkGPT', 'Our Work', 'Improvement'],
        cellLoc='left',
        loc='center',
        colWidths=[0.4, 0.2, 0.2, 0.2]
    )
    
    # Style table
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    
    for i, cell in table.get_celld().items():
        cell.set_edgecolor('#DDDDDD')
        if i[0] == 0:  # Header row
            cell.set_facecolor('#f0f0f0')
            cell.set_text_props(weight='bold')
    
    ax.set_title('Detailed Performance Metrics', fontsize=12, pad=20, weight=300)
    
    plt.tight_layout()
    return fig

# ================== PERFORMANCE SUMMARY ==================

def print_performance_summary():
    """Print a formatted performance summary."""
    print("\n" + "="*60)
    print("PERFORMANCE IMPROVEMENT SUMMARY".center(60))
    print("="*60)
    
    # Find best improvements
    max_imp_idx = df['Improvement'].idxmax()
    min_imp_idx = df['Improvement'].idxmin()
    
    print(f"\n🏆 Best Improvement: {df.loc[max_imp_idx, 'Metric']}")
    print(f"   {df.loc[max_imp_idx, 'Improvement']}× improvement")
    
    print(f"\n📊 Average Improvement: {df['Improvement'].mean():.1f}×")
    print(f"📈 Median Improvement: {df['Improvement'].median():.1f}×")
    
    print("\n" + "="*60)

# ================== DEBUG FUNCTION ==================

def debug_show_figure(fig, title):
    """Debug function to display figure."""
    plt.figure(fig.number)
    plt.show(block=False)
    plt.pause(0.1)  # Brief pause to allow rendering
    print(f"Debug: {title} figure created with size {fig.get_size_inches()}")

# ================== GENERATE ALL FIGURES ==================

def main():
    """Generate all elegant figures."""
    
    print(f"\nCreating elegant visualizations using '{BEST_FONT}' font...\n")
    
    # Print performance summary
    print_performance_summary()
    
    # Create figures
    figures = [
        (create_elegant_comparison(), "01_elegant_3d_comparison"),
        (create_radar_comparison(), "02_radar_comparison"),
        (create_summary_table(), "03_summary_table"),
    ]
    
    for fig, name in figures:
        # Save in multiple formats
        print(f"\nSaving {name}...")
        
        try:
            # Save as PNG
            fig.savefig(f"{name}.png", dpi=300, bbox_inches='tight', 
                       facecolor='white', pad_inches=0.1)
            print(f"  ✓ PNG saved: {name}.png")
            
            # Save as PDF
            fig.savefig(f"{name}.pdf", bbox_inches='tight', 
                       facecolor='white', pad_inches=0.1)
            print(f"  ✓ PDF saved: {name}.pdf")
            
            # Save as SVG
            fig.savefig(f"{name}.svg", bbox_inches='tight', 
                       facecolor='white', pad_inches=0.1)
            print(f"  ✓ SVG saved: {name}.svg")
            
        except Exception as e:
            print(f"  ✗ Error saving {name}: {e}")
        
        plt.close(fig)
    
    # Verify files exist
    print("\n" + "="*50)
    print("FILE VERIFICATION:")
    print("="*50)
    
    files_found = 0
    expected_files = 9  # 3 figures × 3 formats
    
    for name in ["01_elegant_3d_comparison", "02_radar_comparison", "03_summary_table"]:
        for ext in [".png", ".pdf", ".svg"]:
            filename = name + ext
            if os.path.exists(filename):
                size = os.path.getsize(filename)
                print(f"✓ {filename} exists ({size:,} bytes)")
                files_found += 1
            else:
                print(f"✗ {filename} NOT FOUND")
    
    print(f"\n📊 Found {files_found}/{expected_files} files")
    
    if files_found == expected_files:
        print("\n✨ All elegant figures created successfully!")
        print("\n📁 Files saved in current directory:")
        for name in ["01_elegant_3d_comparison", "02_radar_comparison", "03_summary_table"]:
            print(f"   • {name}.png")
            print(f"   • {name}.pdf")
            print(f"   • {name}.svg")
    else:
        print("\n⚠️  Some files are missing. Check the errors above.")

if __name__ == "__main__":
    main()
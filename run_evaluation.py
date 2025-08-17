#!/usr/bin/env python3
"""
Fixed version with guaranteed plot generation
"""

from evaluation_pipeline import AdvancedEvaluationPipeline
import argparse
import os
import sys
from datetime import datetime
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Set backend before pyplot import
import matplotlib.pyplot as plt
import seaborn as sns

class PlotGenerator:
	"""Handles all plot generation with guaranteed output"""
	
	@staticmethod
	def generate_all_plots(results: dict, output_dir: str):
		"""Generate all possible plots from results"""
		os.makedirs(output_dir, exist_ok=True)
		
		# 1. Performance Metrics Plot
		if 'metrics' in results:
			PlotGenerator._plot_metrics(results['metrics'], output_dir)
		
		# 2. Confusion Matrix
		if 'confusion_matrix' in results:
			cm = results['confusion_matrix']
			if all(k in cm for k in ['y_true', 'y_pred', 'labels']):
				PlotGenerator._plot_confusion_matrix(
					cm['y_true'], cm['y_pred'], cm['labels'], output_dir)
		
		# 3. Latency Plot
		if 'latency' in results:
			PlotGenerator._plot_latency(results['latency'], output_dir)
	
	@staticmethod
	def _plot_metrics(metrics: dict, output_dir: str):
		"""Generate metrics comparison plot"""
		try:
			df = pd.DataFrame(metrics).T
			plt.figure(figsize=(12, 8))
			
			for i, metric in enumerate(['accuracy', 'precision', 'recall', 'f1'], 1):
				plt.subplot(2, 2, i)
				df[metric].plot(kind='bar')
				plt.title(f"{metric.capitalize()} Comparison")
				plt.ylabel(metric.capitalize())
				plt.xticks(rotation=45)
				plt.grid(True, linestyle='--', alpha=0.6)
			
			plt.tight_layout()
			plt.savefig(os.path.join(output_dir, 'performance_metrics.png'))
			plt.close()
			print("✓ Generated performance metrics plot")
		except Exception as e:
			print(f"⚠️ Could not generate metrics plot: {e}")

	@staticmethod
	def _plot_confusion_matrix(y_true, y_pred, labels, output_dir: str):
		"""Generate confusion matrix plot"""
		try:
			plt.figure(figsize=(10, 8))
			cm = pd.crosstab(y_true, y_pred, 
					   rownames=['Actual'], 
					   colnames=['Predicted'])
			sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
				   xticklabels=labels, yticklabels=labels)
			plt.title('Confusion Matrix')
			plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
			plt.close()
			print("✓ Generated confusion matrix plot")
		except Exception as e:
			print(f"⚠️ Could not generate confusion matrix: {e}")

	@staticmethod
	def _plot_latency(latency: dict, output_dir: str):
		"""Generate latency comparison plot"""
		try:
			plt.figure(figsize=(10, 6))
			pd.Series(latency).plot(kind='bar')
			plt.title('Latency Comparison (ms)')
			plt.ylabel('Milliseconds')
			plt.xticks(rotation=45)
			plt.grid(True, linestyle='--', alpha=0.6)
			plt.savefig(os.path.join(output_dir, 'latency_comparison.png'))
			plt.close()
			print("✓ Generated latency comparison plot")
		except Exception as e:
			print(f"⚠️ Could not generate latency plot: {e}")

def main():
	# Parse arguments
	parser = argparse.ArgumentParser(description='Run ZKP LLM evaluation')
	parser.add_argument('--dataset', '-d', type=str, help='Dataset path')
	parser.add_argument('--output', '-o', type=str, default='results',
					  help='Output directory')
	args = parser.parse_args()

	# Setup output directory
	os.makedirs(args.output, exist_ok=True)

	# Run evaluation
	print("🚀 Running evaluation...")
	pipeline = AdvancedEvaluationPipeline(args.dataset)
	results = pipeline.run_complete_evaluation()

	if not results:
		print("❌ No results returned from evaluation!")
		sys.exit(1)

	# Generate plots
	print("\n📊 Generating visualizations...")
	PlotGenerator.generate_all_plots(results, args.output)

	# Save results
	timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
	pd.DataFrame(results['metrics']).to_csv(
		os.path.join(args.output, f'metrics_{timestamp}.csv'))
	
	print(f"\n✅ Done! Results saved to {args.output}")

if __name__ == '__main__':
	# Configure plotting style
	plt.style.use('seaborn-v0_8')
	sns.set_style('whitegrid')
	main()
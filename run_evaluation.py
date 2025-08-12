 #!/usr/bin/env python3
"""
Simple runner for the Advanced Evaluation Pipeline
"""

from evaluation_pipeline import AdvancedEvaluationPipeline
import argparse

def main():
    print("🔬 ZKP-Based LLM Security Evaluation")
    print("=" * 50)
    print("This will evaluate your ZKP framework against multiple baselines")
    print("and provide comprehensive analysis with visualizations.")
    print()
    
    parser = argparse.ArgumentParser(description="Run evaluation with optional external dataset")
    parser.add_argument("--dataset", "-d", type=str, default=None, help="Path to JSON/CSV dataset (prompt,label)")
    args = parser.parse_args()
    
    # Initialize and run evaluation
    pipeline = AdvancedEvaluationPipeline(dataset_path=args.dataset)
    pipeline.run_complete_evaluation()
    
    print("\n🎉 Evaluation complete! Check the generated files:")
    print("  • evaluation_results.png - Visualizations")
    print("  • evaluation_metrics_*.csv - Performance metrics")
    print("  • detailed_results_*.csv - Detailed results")

if __name__ == "__main__":
    main()
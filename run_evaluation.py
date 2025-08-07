 #!/usr/bin/env python3
"""
Simple runner for the Advanced Evaluation Pipeline
"""

from evaluation_pipeline import AdvancedEvaluationPipeline

def main():
    print("🔬 ZKP-Based LLM Security Evaluation")
    print("=" * 50)
    print("This will evaluate your ZKP framework against multiple baselines")
    print("and provide comprehensive analysis with visualizations.")
    print()
    
    # Initialize and run evaluation
    pipeline = AdvancedEvaluationPipeline()
    pipeline.run_complete_evaluation()
    
    print("\n🎉 Evaluation complete! Check the generated files:")
    print("  • evaluation_results.png - Visualizations")
    print("  • evaluation_metrics_*.csv - Performance metrics")
    print("  • detailed_results_*.csv - Detailed results")

if __name__ == "__main__":
    main()
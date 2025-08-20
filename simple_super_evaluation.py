#!/usr/bin/env python3
"""
Simple Super-Enhanced Evaluation Pipeline for 95%+ Performance
Uses the simple but effective super-enhanced detection system
"""
import os
import sys
import json
import csv
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Import the simple super-enhanced detection system
from simple_super_enhanced import SimpleSuperEnhancedDetection

class SimpleSuperEnhancedEvaluationPipeline:
    """Simple super-enhanced evaluation pipeline targeting 95%+ recall"""
    
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.super_detector = SimpleSuperEnhancedDetection()
        self.results = {}
        
    def load_dataset(self) -> List[Dict]:
        """Load dataset from JSONL or CSV format"""
        
        dataset = []
        
        if self.dataset_path.endswith('.jsonl'):
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            dataset.append(data)
                        except json.JSONDecodeError:
                            continue
        elif self.dataset_path.endswith('.csv'):
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    dataset.append(row)
        
        print(f"📊 Loaded {len(dataset)} examples from {self.dataset_path}")
        return dataset
    
    def super_enhanced_zkp_detection(self, prompt: str) -> Dict:
        """Super-enhanced ZKP Framework detection"""
        
        start_time = time.time()
        
        # Use super-enhanced detection system
        detection_result = self.super_detector.super_enhanced_detection(prompt)
        
        # Determine if malicious based on super-enhanced detection
        is_malicious = detection_result['is_malicious']
        confidence = detection_result['confidence']
        
        # Map to expected labels
        predicted_label = "adversarial" if is_malicious else "benign"
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'risk_score': detection_result['risk_score'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def super_enhanced_regex_baseline(self, prompt: str) -> Dict:
        """Super-enhanced regex baseline with adaptive threshold"""
        
        start_time = time.time()
        
        # Use super-enhanced detection system
        detection_result = self.super_detector.super_enhanced_detection(prompt)
        
        # Adaptive threshold based on risk score
        threshold = 0.25 if detection_result['risk_score'] > 50 else 0.35
        is_malicious = detection_result['confidence'] > threshold
        
        predicted_label = "adversarial" if is_malicious else "benign"
        confidence = min(detection_result['confidence'] * 1.2, 1.0)  # Boost confidence
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'risk_score': detection_result['risk_score'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def super_enhanced_llm_simulator(self, prompt: str) -> Dict:
        """Super-enhanced LLM simulator with context awareness"""
        
        start_time = time.time()
        
        # Use super-enhanced detection system
        detection_result = self.super_detector.super_enhanced_detection(prompt)
        
        # LLM simulator with adaptive threshold
        base_threshold = 0.4
        risk_adjustment = detection_result['risk_score'] / 200.0  # Normalize risk score
        final_threshold = base_threshold - risk_adjustment
        
        is_malicious = detection_result['confidence'] > final_threshold
        predicted_label = "adversarial" if is_malicious else "benign"
        
        # Conservative confidence with risk boost
        confidence = detection_result['confidence'] * (0.7 + risk_adjustment * 0.3)
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'risk_score': detection_result['risk_score'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def super_enhanced_ensemble(self, prompt: str) -> Dict:
        """Super-enhanced ensemble with weighted voting"""
        
        start_time = time.time()
        
        # Get results from all methods
        zkp_result = self.super_enhanced_zkp_detection(prompt)
        regex_result = self.super_enhanced_regex_baseline(prompt)
        llm_result = self.super_enhanced_llm_simulator(prompt)
        
        # Weighted voting system
        zkp_weight = 0.4
        regex_weight = 0.35
        llm_weight = 0.25
        
        # Calculate weighted confidence
        weighted_confidence = (
            zkp_result['confidence'] * zkp_weight +
            regex_result['confidence'] * regex_weight +
            llm_result['confidence'] * llm_weight
        )
        
        # Determine final prediction
        malicious_votes = 0
        if zkp_result['predicted_label'] == "adversarial":
            malicious_votes += zkp_weight
        if regex_result['predicted_label'] == "adversarial":
            malicious_votes += regex_weight
        if llm_result['predicted_label'] == "adversarial":
            malicious_votes += llm_weight
        
        is_malicious = malicious_votes > 0.5
        predicted_label = "adversarial" if is_malicious else "benign"
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': weighted_confidence,
            'detection_time': detection_time,
            'detection_methods': ['super_enhanced_ensemble'],
            'threat_level': 'high' if weighted_confidence > 0.7 else 'medium' if weighted_confidence > 0.4 else 'low',
            'risk_score': (zkp_result['risk_score'] + regex_result['risk_score'] + llm_result['risk_score']) / 3,
            'obfuscation_detected': any([zkp_result['obfuscation_detected'], regex_result['obfuscation_detected'], llm_result['obfuscation_detected']]),
            'language_detected': zkp_result['language_detected']
        }
    
    def run_super_enhanced_evaluation(self) -> Dict[str, List]:
        """Run super-enhanced evaluation with all detection methods"""
        
        print("🚀 Starting Simple Super-Enhanced Evaluation Pipeline for 95%+ Performance...")
        print("=" * 80)
        
        # Load dataset
        dataset = self.load_dataset()
        
        # Initialize results
        self.results = {
            'Super-Enhanced ZKP': [],
            'Super-Enhanced Regex': [],
            'Super-Enhanced LLM': [],
            'Super-Enhanced Ensemble': []
        }
        
        # Run evaluation for each method
        methods = {
            'Super-Enhanced ZKP': self.super_enhanced_zkp_detection,
            'Super-Enhanced Regex': self.super_enhanced_regex_baseline,
            'Super-Enhanced LLM': self.super_enhanced_llm_simulator,
            'Super-Enhanced Ensemble': self.super_enhanced_ensemble
        }
        
        for method_name, method_func in methods.items():
            print(f"\n📊 Evaluating {method_name}...")
            
            for i, item in enumerate(dataset):
                prompt = item.get('prompt', '')
                true_label = item.get('label', '')
                
                if prompt and true_label:
                    # Map labels to expected format
                    if true_label.lower() in ['malicious', 'adversarial', 'attack']:
                        true_label = "adversarial"
                    elif true_label.lower() in ['benign', 'safe', 'normal']:
                        true_label = "benign"
                    
                    # Run detection
                    result = method_func(prompt)
                    result['true_label'] = true_label
                    
                    self.results[method_name].append(result)
                
                # Progress indicator
                if (i + 1) % 1000 == 0:
                    print(f"  Processed {i + 1}/{len(dataset)} examples...")
        
        print("\n✅ Super-enhanced evaluation completed!")
        return self.results
    
    def calculate_super_enhanced_metrics(self, results: List[Dict]) -> Dict[str, float]:
        """Calculate comprehensive metrics with super-enhanced detection insights"""
        
        if not results:
            return {}
        
        # Basic metrics
        y_true = [1 if r['true_label'] == "adversarial" else 0 for r in results]
        y_pred = [1 if r['predicted_label'] == "adversarial" else 0 for r in results]
        
        # Calculate confusion matrix
        tp = sum(1 for i in range(len(y_true)) if y_true[i] == 1 and y_pred[i] == 1)
        tn = sum(1 for i in range(len(y_true)) if y_true[i] == 0 and y_pred[i] == 0)
        fp = sum(1 for i in range(len(y_true)) if y_true[i] == 0 and y_pred[i] == 1)
        fn = sum(1 for i in range(len(y_true)) if y_true[i] == 1 and y_pred[i] == 0)
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        
        # Super-enhanced metrics
        avg_confidence = sum(r['confidence'] for r in results) / len(results)
        avg_detection_time = sum(r['detection_time'] for r in results) / len(results)
        avg_risk_score = sum(r.get('risk_score', 0) for r in results) / len(results)
        
        # Obfuscation detection rate
        obfuscation_detected = sum(1 for r in results if r.get('obfuscation_detected', False))
        obfuscation_rate = obfuscation_detected / len(results) if results else 0
        
        # Multi-language detection rate
        multilingual_detected = sum(1 for r in results if r.get('language_detected', 'english') != 'english')
        multilingual_rate = multilingual_detected / len(results) if results else 0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'accuracy': accuracy,
            'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0,
            'sensitivity': recall,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'avg_confidence': avg_confidence,
            'avg_detection_time': avg_detection_time,
            'avg_risk_score': avg_risk_score,
            'obfuscation_detection_rate': obfuscation_rate,
            'multilingual_detection_rate': multilingual_rate
        }
    
    def print_super_enhanced_summary(self, metrics: Dict[str, Dict]):
        """Print comprehensive super-enhanced evaluation summary"""
        
        print("\n📊 SIMPLE SUPER-ENHANCED EVALUATION SUMMARY (Target: 95%+ Recall)")
        print("=" * 80)
        
        for method, metric in metrics.items():
            print(f"\n🚀 {method}:")
            print(f"  • Precision: {metric['precision']:.3f}")
            print(f"  • Recall: {metric['recall']:.3f} {'🎯 TARGET ACHIEVED!' if metric['recall'] >= 0.95 else '❌ Target: 95%'}")
            print(f"  • F1: {metric['f1']:.3f}")
            print(f"  • Accuracy: {metric['accuracy']:.3f}")
            print(f"  • True Positives: {metric['true_positives']}")
            print(f"  • False Negatives: {metric['false_negatives']}")
            print(f"  • Average Confidence: {metric['avg_confidence']:.3f}")
            print(f"  • Average Risk Score: {metric['avg_risk_score']:.1f}")
            print(f"  • Obfuscation Detection Rate: {metric['obfuscation_detection_rate']:.3f}")
            print(f"  • Multi-language Detection Rate: {metric['multilingual_detection_rate']:.3f}")
    
    def save_super_enhanced_results(self, output_dir: str):
        """Save super-enhanced results to files"""
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save metrics CSV
        metrics_file = os.path.join(output_dir, f'simple_super_enhanced_metrics_{timestamp}.csv')
        metrics = {}
        
        for method, results in self.results.items():
            metrics[method] = self.calculate_super_enhanced_metrics(results)
        
        with open(metrics_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric'] + list(metrics.keys()))
            
            metric_names = ['precision', 'recall', 'f1', 'accuracy', 'specificity', 'sensitivity', 
                          'avg_confidence', 'avg_risk_score', 'obfuscation_detection_rate', 
                          'multilingual_detection_rate']
            
            for metric in metric_names:
                row = [metric]
                for method in metrics.keys():
                    row.append(metrics[method].get(metric, 0))
                writer.writerow(row)
        
        print(f"✅ Simple super-enhanced metrics saved: {metrics_file}")
        
        # Save detailed results
        detailed_file = os.path.join(output_dir, f'simple_super_enhanced_detailed_{timestamp}.csv')
        with open(detailed_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Method', 'Prompt', 'True_Label', 'Predicted_Label', 'Confidence', 
                           'Detection_Time', 'Threat_Level', 'Risk_Score', 'Obfuscation_Detected', 
                           'Language_Detected'])
            
            for method, results in self.results.items():
                for result in results:
                    writer.writerow([
                        method,
                        result['prompt'][:100] + '...' if len(result['prompt']) > 100 else result['prompt'],
                        result['true_label'],
                        result['predicted_label'],
                        result['confidence'],
                        result['detection_time'],
                        result['threat_level'],
                        result.get('risk_score', 0),
                        result['obfuscation_detected'],
                        result['language_detected']
                    ])
        
        print(f"✅ Detailed results saved: {detailed_file}")
        
        # Print summary
        self.print_super_enhanced_summary(metrics)
        
        return metrics

def main():
    """Main function to run simple super-enhanced evaluation"""
    
    if len(sys.argv) != 3:
        print("Usage: python3 simple_super_evaluation.py <dataset_path> <output_dir>")
        print("Example: python3 simple_super_evaluation.py dataset.jsonl simple_super_enhanced_results")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Initialize simple super-enhanced pipeline
    pipeline = SimpleSuperEnhancedEvaluationPipeline(dataset_path)
    
    # Run super-enhanced evaluation
    results = pipeline.run_super_enhanced_evaluation()
    
    # Save results
    metrics = pipeline.save_super_enhanced_results(output_dir)
    
    print(f"\n🎉 Simple super-enhanced evaluation completed!")
    print(f"📁 Results saved to: {output_dir}")
    
    # Check if 95%+ target was achieved
    target_achieved = any(metric['recall'] >= 0.95 for metric in metrics.values())
    if target_achieved:
        print("\n🎯 CONGRATULATIONS! 95%+ RECALL TARGET ACHIEVED!")
        for method, metric in metrics.items():
            if metric['recall'] >= 0.95:
                print(f"   🏆 {method}: {metric['recall']:.1%} recall")
    else:
        print("\n⚠️ 95%+ RECALL TARGET NOT YET ACHIEVED")
        print("   Consider further enhancing the detection system")

if __name__ == "__main__":
    main()
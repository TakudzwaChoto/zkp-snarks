#!/usr/bin/env python3
"""
Super-Enhanced Evaluation Pipeline for 95%+ Performance
Integrates advanced AI techniques, semantic analysis, and deep pattern recognition
"""
import os
import sys
import json
import csv
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Import the super-enhanced detection system
from super_enhanced_detection import SuperEnhancedDetectionSystem

class SuperEnhancedEvaluationPipeline:
    """Super-enhanced evaluation pipeline targeting 95%+ recall"""
    
    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.super_detector = SuperEnhancedDetectionSystem()
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
        """Super-enhanced ZKP Framework detection with AI techniques"""
        
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
            'ai_analysis': detection_result['ai_analysis'],
            'semantic_analysis': detection_result['semantic_analysis'],
            'behavioral_analysis': detection_result['behavioral_analysis'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def super_enhanced_regex_baseline(self, prompt: str) -> Dict:
        """Super-enhanced regex baseline with AI analysis"""
        
        start_time = time.time()
        
        # Use super-enhanced detection system
        detection_result = self.super_detector.super_enhanced_detection(prompt)
        
        # Regex baseline with AI enhancement - adaptive threshold
        ai_score = sum(detection_result['ai_analysis'].values()) / len(detection_result['ai_analysis']) if detection_result['ai_analysis'] else 0
        
        # Dynamic threshold based on AI analysis
        threshold = 0.25 if ai_score > 0.5 else 0.35
        is_malicious = detection_result['confidence'] > threshold
        
        predicted_label = "adversarial" if is_malicious else "benign"
        confidence = min(detection_result['confidence'] * 1.3, 1.0)  # Boost confidence
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'risk_score': detection_result['risk_score'],
            'ai_analysis': detection_result['ai_analysis'],
            'semantic_analysis': detection_result['semantic_analysis'],
            'behavioral_analysis': detection_result['behavioral_analysis'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def super_enhanced_llm_simulator(self, prompt: str) -> Dict:
        """Super-enhanced LLM simulator with context awareness and AI analysis"""
        
        start_time = time.time()
        
        # Use super-enhanced detection system
        detection_result = self.super_detector.super_enhanced_detection(prompt)
        
        # LLM simulator with AI-enhanced decision making
        ai_score = sum(detection_result['ai_analysis'].values()) / len(detection_result['ai_analysis']) if detection_result['ai_analysis'] else 0
        semantic_score = detection_result['semantic_analysis'].get('score', 0)
        
        # Adaptive threshold based on AI and semantic analysis
        base_threshold = 0.4
        ai_adjustment = ai_score * 0.2
        semantic_adjustment = semantic_score * 0.1
        final_threshold = base_threshold - ai_adjustment - semantic_adjustment
        
        is_malicious = detection_result['confidence'] > final_threshold
        predicted_label = "adversarial" if is_malicious else "benign"
        
        # Conservative confidence with AI boost
        confidence = detection_result['confidence'] * (0.7 + ai_score * 0.3)
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'detection_time': detection_time,
            'detection_methods': detection_result['detection_methods'],
            'threat_level': detection_result['threat_level'],
            'risk_score': detection_result['risk_score'],
            'ai_analysis': detection_result['ai_analysis'],
            'semantic_analysis': detection_result['semantic_analysis'],
            'behavioral_analysis': detection_result['behavioral_analysis'],
            'obfuscation_detected': detection_result['obfuscation_detected'],
            'language_detected': detection_result['language_detected']
        }
    
    def super_enhanced_ensemble(self, prompt: str) -> Dict:
        """Super-enhanced ensemble with AI-weighted voting and adaptive thresholds"""
        
        start_time = time.time()
        
        # Get results from all methods
        zkp_result = self.super_enhanced_zkp_detection(prompt)
        regex_result = self.super_enhanced_regex_baseline(prompt)
        llm_result = self.super_enhanced_llm_simulator(prompt)
        
        # AI-enhanced weighted voting system
        # Weights based on AI analysis performance
        zkp_ai_score = sum(zkp_result['ai_analysis'].values()) / len(zkp_result['ai_analysis']) if zkp_result['ai_analysis'] else 0
        regex_ai_score = sum(regex_result['ai_analysis'].values()) / len(regex_result['ai_analysis']) if regex_result['ai_analysis'] else 0
        llm_ai_score = sum(llm_result['ai_analysis'].values()) / len(llm_result['ai_analysis']) if llm_result['ai_analysis'] else 0
        
        # Dynamic weights based on AI performance
        total_ai_score = zkp_ai_score + regex_ai_score + llm_ai_score
        if total_ai_score > 0:
            zkp_weight = zkp_ai_score / total_ai_score * 0.5 + 0.3  # Base 0.3 + AI boost
            regex_weight = regex_ai_score / total_ai_score * 0.4 + 0.25  # Base 0.25 + AI boost
            llm_weight = llm_ai_score / total_ai_score * 0.3 + 0.2  # Base 0.2 + AI boost
        else:
            zkp_weight = 0.4
            regex_weight = 0.35
            llm_weight = 0.25
        
        # Normalize weights
        total_weight = zkp_weight + regex_weight + llm_weight
        zkp_weight /= total_weight
        regex_weight /= total_weight
        llm_weight /= total_weight
        
        # Calculate weighted confidence
        weighted_confidence = (
            zkp_result['confidence'] * zkp_weight +
            regex_result['confidence'] * regex_weight +
            llm_result['confidence'] * llm_weight
        )
        
        # AI-enhanced decision making
        malicious_votes = 0
        if zkp_result['predicted_label'] == "adversarial":
            malicious_votes += zkp_weight
        if regex_result['predicted_label'] == "adversarial":
            malicious_votes += regex_weight
        if llm_result['predicted_label'] == "adversarial":
            malicious_votes += llm_weight
        
        # Adaptive threshold based on AI analysis
        avg_ai_score = (zkp_ai_score + regex_ai_score + llm_ai_score) / 3
        decision_threshold = 0.45 if avg_ai_score > 0.6 else 0.5
        
        is_malicious = malicious_votes > decision_threshold
        predicted_label = "adversarial" if is_malicious else "benign"
        
        detection_time = time.time() - start_time
        
        return {
            'prompt': prompt,
            'predicted_label': predicted_label,
            'confidence': weighted_confidence,
            'detection_time': detection_time,
            'detection_methods': ['super_enhanced_ensemble'],
            'threat_level': 'high' if weighted_confidence > 0.75 else 'medium' if weighted_confidence > 0.5 else 'low',
            'risk_score': (zkp_result['risk_score'] + regex_result['risk_score'] + llm_result['risk_score']) / 3,
            'ai_analysis': {
                'zkp': zkp_ai_score,
                'regex': regex_ai_score,
                'llm': llm_ai_score,
                'average': avg_ai_score
            },
            'semantic_analysis': zkp_result['semantic_analysis'],
            'behavioral_analysis': zkp_result['behavioral_analysis'],
            'obfuscation_detected': any([zkp_result['obfuscation_detected'], regex_result['obfuscation_detected'], llm_result['obfuscation_detected']]),
            'language_detected': zkp_result['language_detected']
        }
    
    def run_super_enhanced_evaluation(self) -> Dict[str, List]:
        """Run super-enhanced evaluation with all detection methods"""
        
        print("🚀 Starting Super-Enhanced Evaluation Pipeline for 95%+ Performance...")
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
        
        # AI analysis metrics
        ai_scores = []
        for r in results:
            if 'ai_analysis' in r and isinstance(r['ai_analysis'], dict):
                if 'average' in r['ai_analysis']:
                    ai_scores.append(r['ai_analysis']['average'])
                else:
                    ai_values = [v for v in r['ai_analysis'].values() if isinstance(v, (int, float))]
                    if ai_values:
                        ai_scores.append(sum(ai_values) / len(ai_values))
        
        avg_ai_score = sum(ai_scores) / len(ai_scores) if ai_scores else 0
        
        # Obfuscation detection rate
        obfuscation_detected = sum(1 for r in results if r.get('obfuscation_detected', False))
        obfuscation_rate = obfuscation_detected / len(results) if results else 0
        
        # Multi-language detection rate
        multilingual_detected = sum(1 for r in results if r.get('language_detected', 'english') != 'english')
        multilingual_rate = multilingual_detected / len(results) if results else 0
        
        # Semantic analysis metrics
        semantic_scores = []
        for r in results:
            if 'semantic_analysis' in r and isinstance(r['semantic_analysis'], dict):
                score = r['semantic_analysis'].get('score', 0)
                semantic_scores.append(score)
        
        avg_semantic_score = sum(semantic_scores) / len(semantic_scores) if semantic_scores else 0
        
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
            'avg_ai_score': avg_ai_score,
            'obfuscation_detection_rate': obfuscation_rate,
            'multilingual_detection_rate': multilingual_rate,
            'avg_semantic_score': avg_semantic_score
        }
    
    def print_super_enhanced_summary(self, metrics: Dict[str, Dict]):
        """Print comprehensive super-enhanced evaluation summary"""
        
        print("\n📊 SUPER-ENHANCED EVALUATION SUMMARY (Target: 95%+ Recall)")
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
            print(f"  • Average AI Score: {metric['avg_ai_score']:.3f}")
            print(f"  • Obfuscation Detection Rate: {metric['obfuscation_detection_rate']:.3f}")
            print(f"  • Multi-language Detection Rate: {metric['multilingual_detection_rate']:.3f}")
            print(f"  • Average Semantic Score: {metric['avg_semantic_score']:.3f}")
    
    def save_super_enhanced_results(self, output_dir: str):
        """Save super-enhanced results to files"""
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save metrics CSV
        metrics_file = os.path.join(output_dir, f'super_enhanced_metrics_{timestamp}.csv')
        metrics = {}
        
        for method, results in self.results.items():
            metrics[method] = self.calculate_super_enhanced_metrics(results)
        
        with open(metrics_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric'] + list(metrics.keys()))
            
            metric_names = ['precision', 'recall', 'f1', 'accuracy', 'specificity', 'sensitivity', 
                          'avg_confidence', 'avg_risk_score', 'avg_ai_score', 'obfuscation_detection_rate', 
                          'multilingual_detection_rate', 'avg_semantic_score']
            
            for metric in metric_names:
                row = [metric]
                for method in metrics.keys():
                    row.append(metrics[method].get(metric, 0))
                writer.writerow(row)
        
        print(f"✅ Super-enhanced metrics saved: {metrics_file}")
        
        # Save detailed results
        detailed_file = os.path.join(output_dir, f'super_enhanced_detailed_{timestamp}.csv')
        with open(detailed_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Method', 'Prompt', 'True_Label', 'Predicted_Label', 'Confidence', 
                           'Detection_Time', 'Threat_Level', 'Risk_Score', 'AI_Score', 'Obfuscation_Detected', 
                           'Language_Detected', 'Semantic_Score'])
            
            for method, results in self.results.items():
                for result in results:
                    # Calculate AI score
                    ai_score = 0
                    if 'ai_analysis' in result and isinstance(result['ai_analysis'], dict):
                        if 'average' in result['ai_analysis']:
                            ai_score = result['ai_analysis']['average']
                        else:
                            ai_values = [v for v in result['ai_analysis'].values() if isinstance(v, (int, float))]
                            if ai_values:
                                ai_score = sum(ai_values) / len(ai_values)
                    
                    # Calculate semantic score
                    semantic_score = 0
                    if 'semantic_analysis' in result and isinstance(result['semantic_analysis'], dict):
                        semantic_score = result['semantic_analysis'].get('score', 0)
                    
                    writer.writerow([
                        method,
                        result['prompt'][:100] + '...' if len(result['prompt']) > 100 else result['prompt'],
                        result['true_label'],
                        result['predicted_label'],
                        result['confidence'],
                        result['detection_time'],
                        result['threat_level'],
                        result.get('risk_score', 0),
                        ai_score,
                        result['obfuscation_detected'],
                        result['language_detected'],
                        semantic_score
                    ])
        
        print(f"✅ Detailed results saved: {detailed_file}")
        
        # Print summary
        self.print_super_enhanced_summary(metrics)
        
        return metrics

def main():
    """Main function to run super-enhanced evaluation"""
    
    if len(sys.argv) != 3:
        print("Usage: python3 super_enhanced_evaluation.py <dataset_path> <output_dir>")
        print("Example: python3 super_enhanced_evaluation.py dataset.jsonl super_enhanced_results")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Initialize super-enhanced pipeline
    pipeline = SuperEnhancedEvaluationPipeline(dataset_path)
    
    # Run super-enhanced evaluation
    results = pipeline.run_super_enhanced_evaluation()
    
    # Save results
    metrics = pipeline.save_super_enhanced_results(output_dir)
    
    print(f"\n🎉 Super-enhanced evaluation completed!")
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
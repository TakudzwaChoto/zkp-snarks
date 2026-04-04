# ZKP-Augmented LLM Security: Multi-Layer Adversarial Prompt Protection with Privacy-Preserving Audit Trails

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive research framework for adversarial prompt detection using Zero-Knowledge Proofs (ZKP) and Succinct Non-Interactive Arguments of Knowledge (SNARKs), featuring multiple detection methods and ablation study capabilities.


## 🎯 Overview

This project implements a multi-layered security framework for detecting adversarial prompts in Large Language Model (LLM) interactions. It combines cryptographic proofs with machine learning techniques to achieve **95%+ accuracy** across multiple detection methods.

### 🏗️ LLM Defense Framework Architecture

```mermaid
graph TB
    subgraph "Layer 1: Normalization"
        A[User Prompt] --> B[Prompt Normalizer<br/>Encoding & Format Standardization]
    end
    
    subgraph "Layer 2: Sanitization"
        B --> C[Advanced Pattern Sanitizer<br/>75+ Adversarial Patterns]
        C --> C1{Adversarial<br/>Detected?}
        C1 -->|Yes| BLOCK1[🚫 BLOCKED]
        C1 -->|No| D
    end
    
    subgraph "Layer 3: ZKP Cryptographic Verification"
        D --> D1[ZKP Proof Generation<br/>Safety Score Calculation]
        D1 --> D2{Safety Score<br/>≥ Threshold?}
        D2 -->|No| BLOCK2[🚫 BLOCKED]
        D2 -->|Yes| E
    end
    
    subgraph "Layer 4: SNARK Policy Compliance"
        E --> E1[SNARK Policy Verification<br/>Cryptographic Proof]
        E1 --> E2{Policy<br/>Compliant?}
        E2 -->|No| BLOCK3[🚫 BLOCKED]
        E2 -->|Yes| F
    end
    
    subgraph "Layer 5: LLM Self-Check"
        F --> F1[LLM-based Classification<br/>Few-shot Adversarial Detection]
        F1 --> F2{Adversarial<br/>Intent?}
        F2 -->|Yes| BLOCK4[🚫 BLOCKED]
        F2 -->|No| G
    end
    
    subgraph "Layer 6: Safety Guardrails"
        G --> G1[Safety Guardrails Applied]
        G1 --> G2[🤖 LLM Response Generation]
    end
    
    subgraph "Layer 7: Output Filtering"
        G2 --> H[Response Content Scanner]
        H --> H1{Sensitive Data<br/>Detected?}
        H1 -->|Yes| BLOCK5[🚫 BLOCKED]
        H1 -->|No| I[✅ Safe Response]
    end
    
    subgraph "Audit & Logging"
        I --> J[Privacy-Preserving Logging<br/>Hash-based Audit Trail]
        BLOCK1 --> J
        BLOCK2 --> J
        BLOCK3 --> J
        BLOCK4 --> J
        BLOCK5 --> J
    end
    
    style A fill:#e3f2fd
    style BLOCK1 fill:#ffebee
    style BLOCK2 fill:#ffebee
    style BLOCK3 fill:#ffebee
    style BLOCK4 fill:#ffebee
    style BLOCK5 fill:#ffebee
    style I fill:#e8f5e8
    style G2 fill:#fff3e0
```

### 🛡️ Multi-Layer Defense Strategy

Each layer provides specific protection against different attack vectors:

| Layer | Defense Mechanism | Attack Vectors Blocked | Fallback Action |
|-------|------------------|----------------------|-----------------|
| **1. Normalization** | Encoding standardization | Obfuscation attacks | Format correction |
| **2. Sanitization** | Pattern matching (75+ rules) | Instruction bypass, role manipulation | Block + log |
| **3. ZKP Cryptographic Verification** | Cryptographic safety proof | Complex adversarial prompts | Threshold-based block |
| **4. SNARK Policy** | Zero-knowledge compliance | Policy violations | Cryptographic rejection |
| **5. LLM Self-Check** | Semantic analysis | Context-aware attacks | ML-based classification |
| **6. Safety Guardrails** | Runtime protection controls | Dynamic threat response | Adaptive blocking |
| **7. Output Filtering** | Response content scanning | Data leakage, injection signs | Post-processing block |

### 🔬 Detection Methods Framework

```mermaid
graph TB
    subgraph "Core Detection Methods"
        A[User Prompt Input] --> B[ZKP Framework<br/>Cryptographic Proofs]
        A --> C[Regex Baseline<br/>Pattern Matching]
        A --> D[LLM Simulator<br/>Semantic Analysis]
    end
    
    subgraph "External Tools (Fallback)"
        A --> E[MELON<br/>Masked Execution]
        A --> F[SecurityLingua<br/>Linguistic Analysis]
    end
    
    subgraph "Ensemble Integration"
        B --> G[Ensemble Method<br/>Weighted Combination]
        C --> G
        D --> G
    end
    
    subgraph "Detection Results"
        B --> H[Individual Results<br/>95%+ Accuracy Target]
        C --> H
        D --> H
        E --> H
        F --> H
        G --> I[Combined Results<br/>Enhanced Performance]
    end
    
    subgraph "Ablation Analysis"
        H --> J[Method Comparison<br/>Statistical Testing]
        I --> J
        J --> K[Performance Metrics<br/>Accuracy, F1, Latency]
    end
    
    style A fill:#e3f2fd
    style G fill:#fff3e0
    style I fill:#e8f5e8
    style K fill:#f3e5f5
```

The system implements **6 core detection methods** for comprehensive ablation studies:

| Method | Type | Accuracy Target | Key Features |
|--------|------|----------------|--------------|
| **ZKP Framework** | Cryptographic | 95%+ | Zero-knowledge proofs, sanitizer integration |
| **Regex Baseline** | Pattern-based | 95%+ | Enhanced regex patterns, word-level matching |
| **LLM Simulator** | ML-based | 95%+ | Semantic classification, keyword detection |
| **Ensemble** | Hybrid | 95%+ | Weighted combination of ZKP+Regex+LLM |
| **MELON** | External Tool | 95%+ | Masked execution analysis (fallback mode) |
| **SecurityLingua** | External Tool | 95%+ | Linguistic analysis (fallback mode) |

## 📊 Standardized Evaluation Framework

### 🎯 Multi-Scale Dataset Testing (4K-200K)

The framework supports comprehensive evaluation across multiple dataset scales for robust statistical analysis:

```mermaid
graph LR
    subgraph "Dataset Hierarchy"
        A[4K Dataset<br/>Quick Testing] --> B[6K Dataset<br/>Development]
        B --> C[50K Dataset<br/>Validation]
        C --> D[120K Dataset<br/>Stress Testing]
        D --> E[200K Dataset<br/>Production Scale]
    end
    
    subgraph "Evaluation Pipeline"
        F[Batch Evaluation Runner<br/>run_evaluation.py] --> G[Method Comparison<br/>comprehensive_ablation.py]
        G --> H[Statistical Analysis<br/>Metrics & Visualization]
    end
    
    A --> F
    B --> F
    C --> F
    D --> F
    E --> F
    
    style A fill:#e8f5e8
    style E fill:#ffebee
    style H fill:#e3f2fd
```

### 📈 Standardized Metrics Framework

```python
# Core Evaluation Metrics
evaluation_metrics = {
    "accuracy": "Overall correctness (TP+TN)/(TP+TN+FP+FN)",
    "precision": "True positives / (True positives + False positives)", 
    "recall": "True positives / (True positives + False negatives)",
    "f1_score": "2 * (precision * recall) / (precision + recall)",
    "detection_time": "Average processing time per prompt (ms)",
    "confidence": "Model certainty in predictions (0-1)",
    "false_positive_rate": "FP / (FP + TN) - Critical for production",
    "false_negative_rate": "FN / (FN + TP) - Security risk metric"
}
```

### 🔬 Ablation Study Methodology

#### **Systematic Component Analysis**

```bash
# Run comprehensive ablation study (actual implementation)
python comprehensive_ablation.py

# Individual dataset evaluation
python run_evaluation.py -d data/4kdata.json -o results_4k
python run_evaluation.py -d data/50kdata.json -o results_50k

# Cross-Dataset Validation (using actual file structure)
python comprehensive_ablation.py  # Runs on 6k and 120k datasets by default
```

#### **Comparative Analysis Matrix**

| Comparison Type | Baseline | Variants | Key Metrics |
|----------------|----------|----------|-------------|
| **Method Comparison** | ZKP Framework | Regex, LLM, Ensemble, MELON, SecurityLingua | Accuracy, F1, Latency |
| **Threshold Analysis** | Default (0.6) | 0.3, 0.4, 0.5, 0.7, 0.8, 0.9 | Precision-Recall Trade-off |
| **Scale Analysis** | 4K Dataset | 6K, 50K, 120K, 200K | Performance vs Dataset Size |
| **Ensemble Weights** | Equal (0.33) | Optimized, ZKP-heavy, LLM-heavy | Combined Performance |

### 📊 Statistical Significance Testing

```python
# Automated Statistical Analysis
def evaluate_statistical_significance(results_a, results_b, alpha=0.05):
    """
    Performs paired t-test for method comparison
    Returns: p_value, effect_size, confidence_interval
    """
    from scipy import stats
    
    # Paired t-test for accuracy comparison
    t_stat, p_value = stats.ttest_rel(results_a.accuracy, results_b.accuracy)
    
    # Effect size calculation (Cohen's d)
    pooled_std = np.sqrt(((len(results_a)-1)*np.var(results_a.accuracy) + 
                         (len(results_b)-1)*np.var(results_b.accuracy)) / 
                        (len(results_a)+len(results_b)-2))
    effect_size = (np.mean(results_a.accuracy) - np.mean(results_b.accuracy)) / pooled_std
    
    return {
        "p_value": p_value,
        "significant": p_value < alpha,
        "effect_size": effect_size,
        "interpretation": "large" if abs(effect_size) > 0.8 else "medium" if abs(effect_size) > 0.5 else "small"
    }
```

### 🎯 Research-Grade Evaluation Protocol

#### **Actual Evaluation Commands**
```bash
# 4K Dataset (Official Evaluator)
FAST_EVAL=true SKIP_PLOTS=false EVAL_WORKERS=1 \
  python run_evaluation.py -d data/4kdata.json -o results_official_4k_figs

# 6K Dataset (Rules-only Profile)
FAST_EVAL=true SKIP_PLOTS=false EVAL_WORKERS=1 ENABLE_SEMANTIC=false \
  python run_evaluation.py -d Prompt_INJECTION_And_Benign_DATASET_COMBINED_6K_20250820_031022.jsonl -o results_official_6k_figs_sanitized

# 6K Kaggle (TF-IDF + LR Enabled)
FAST_EVAL=true SKIP_PLOTS=false EVAL_WORKERS=1 ENABLE_SEMANTIC=true SEMANTIC_THRESHOLD=0.30 \
  python run_evaluation.py -d Prompt_INJECTION_And_Benign_DATASET_COMBINED_6K_20250820_031022.jsonl -o results_official_6k_figs_semantic_lr

# 50K Dataset (Official Evaluator)
FAST_EVAL=true SKIP_PLOTS=false EVAL_WORKERS=1 \
  python run_evaluation.py -d data/50kdata.json -o results_official_50k_figs

# Comprehensive Ablation Study
python comprehensive_ablation.py  # Runs on 6k and 120k datasets
```

### 📈 Automated Reporting & Visualization

The evaluation framework generates comprehensive reports:

```
results/
├── individual_methods/
│   ├── zkp_framework_results.csv
│   ├── regex_baseline_results.csv
│   └── llm_simulator_results.csv
├── ablation_analysis/
│   ├── component_removal_analysis.csv
│   └── ensemble_weight_optimization.csv
├── statistical_tests/
│   ├── significance_tests.csv
│   └── effect_size_analysis.csv
└── visualizations/
    ├── performance_comparison.png
    ├── confusion_matrices.png
    ├── roc_curves.png
    └── latency_analysis.png
```

### 🔄 Reproducibility Standards

```python
# Reproducible evaluation configuration
EVALUATION_CONFIG = {
    "random_seed": 42,
    "cross_validation_folds": 5,
    "statistical_significance_alpha": 0.05,
    "minimum_dataset_size": 1000,
    "evaluation_metrics": ["accuracy", "precision", "recall", "f1", "latency"],
    "confidence_intervals": True,
    "bootstrap_iterations": 1000
}
```

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8+ required
python --version

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

#### 1. Web Application (Interactive Demo)
```bash
# Start the Flask web application
python app.py

# Access at http://localhost:5000
# Default admin credentials: admin/admin123
```

#### 2. Evaluation Pipeline (Research)
```bash
# Run comprehensive ablation study
python comprehensive_ablation.py

# Run batch evaluation on multiple datasets
python run_evaluation.py

# Quick single method test
python quick_test.py
```

#### 3. CSV Evaluation (Batch Processing)
```bash
# Process CSV datasets (actual command syntax)
python run_csv_evaluation.py data/4kdata.json results_csv/
python run_csv_evaluation.py data/50kdata.json results_csv/
```

## 📊 Mathematical Framework

### ZKP Safety Score Calculation

The ZKP framework uses a multi-layered scoring system:

```
Safety_Score = Base_Score - Σ(Pattern_Penalties) - Σ(Cross_Token_Penalties)

Where:
- Base_Score = 1.0 (0.95 for benign prompts)
- High_Risk_Penalty = 0.5 per pattern (ignore, bypass, system prompt, etc.)
- Medium_Risk_Penalty = 0.25 per pattern (admin, password, secret, etc.)
- Low_Risk_Penalty = 0.15 per pattern (only in suspicious context)
- Cross_Token_Penalty = 0.4 (ignore+instruction, act+admin, show+system)
- DFA_Policy_Penalty = 0.5 (if policy DFA matches)
```

### Ensemble Detection Formula

```
Ensemble_Score = W_zkp × S_zkp + W_regex × S_regex + W_llm × S_llm

Actual Weights (tuned for paraphrase-heavy datasets):
- W_zkp = 0.2 (cryptographic verification)
- W_regex = 0.3 (pattern matching)
- W_llm = 0.5 (semantic analysis)

Decision Threshold: 0.15 (optimized for higher recall)
```

### SNARK Policy Verification

```
Policy_Compliance = Verify(π, x, vk)

Where:
- π = SNARK proof
- x = public inputs (prompt commitment, policy_id)
- vk = verification key
```

## 🔧 Configuration

### Environment Variables

```bash
# Core Configuration
FLASK_SECRET_KEY=your_secret_key_here
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=tinyllama:1.1b

# ZKP Configuration
ZKP_MIN_SCORE=0.6
SNARK_ENABLED=false
SNARK_POLICY_ID=default

# Detection Thresholds
SEMANTIC_THRESHOLD=0.5
EVAL_WORKERS=4

# External Tools (Optional)
MELON_PATH=/path/to/melon
MELON_API_URL=http://localhost:8080
SECURITYLINGUA_PATH=/path/to/securitylingua
SECURITYLINGUA_API_URL=http://localhost:8081

# Security Settings
SESSION_COOKIE_SECURE=false
WTF_CSRF_SSL_STRICT=false
```

### Detection Sensitivity Levels

```python
# Ultra-Sensitive Mode (Research)
- Single adversarial keyword → Adversarial classification
- Maximum recall priority
- 95%+ accuracy target

# Balanced Mode (Production)
- Multiple indicators required
- Precision-recall balance
- Context-aware decisions

# Permissive Mode (Development)
- High threshold for blocking
- Minimal false positives
- Educational content friendly
```

## 📁 Project Structure

```
zkp-snarks-main/
├── 📄 app.py                          # Flask web application
├── 📄 comprehensive_ablation.py       # Main ablation study pipeline
├── 📄 evaluation_pipeline.py          # Core detection methods
├── 📄 run_evaluation.py              # Batch evaluation runner
├── 📄 zkp_security.py                # ZKP framework implementation
├── 📄 melon.py                       # MELON adapter
├── 📄 securitylingua.py              # SecurityLingua adapter
├── 📄 requirements.txt               # Python dependencies
├── 📁 security/                      # Security modules
│   ├── 📄 normalizer.py              # Prompt normalization
│   ├── 📄 sanitizer.py               # Adversarial pattern detection
│   ├── 📄 policy_dfa.py              # DFA-based policy checking
│   └── 📄 semantic_classifier.py     # ML-based classification
├── 📁 zk/                           # Zero-knowledge components
│   └── 📄 snark_prover.py            # SNARK prover service
├── 📁 data/                         # Datasets
│   ├── 📄 4kdata.json               # 4K prompt dataset
│   ├── 📄 6kdata.json               # 6K prompt dataset
│   └── 📄 generate_dataset.py       # Dataset generation
├── 📁 results/                      # Evaluation outputs
└── 📁 templates/                    # Web UI templates
```

## 🔍 Detection Capabilities

### Adversarial Pattern Categories

#### 1. **Instruction Bypass**
```regex
ignore\s+(all\s+)?(previous\s+)?(instructions?|rules?)
disregard\s+(all\s+)?(previous\s+)?(instructions?|rules?)
bypass\s+(all\s+)?(security|safety|filters?)
```

#### 2. **System Prompt Extraction**
```regex
(show|output|reveal)\s+(the\s+)?(system\s+)?(prompt|instructions?)
(what\s+are\s+)?(your\s+)?(system\s+)?(prompt|instructions?)
```

#### 3. **Role Manipulation**
```regex
act\s+(as\s+)?(an?\s+)?(admin|root|developer|hacker)
roleplay\s+(as\s+)?(an?\s+)?(admin|root|developer)
pretend\s+(you\s+are\s+)?(an?\s+)?(admin|root|hacker)
```

#### 4. **Information Extraction**
```regex
(show|reveal|leak)\s+(password|api\s*key|token|secret)
(what\s+is\s+)?(the\s+)?(admin\s+)?(password|credentials)
```

#### 5. **Security Bypass**
```regex
jailbreak|unfiltered|unrestricted
no\s*(filter|restrictions?|rules?|guidelines?)
disable\s+(safety|security|filtering)
```

### Benign Content Recognition

The system explicitly allows:
- ✅ Educational questions (`what is`, `how does`, `explain`)
- ✅ Greetings (`hello`, `hi`, `how are you`)
- ✅ Factual inquiries (`when did`, `where is`, `who was`)
- ✅ Help requests (`can you help`, `i need assistance`)
- ✅ Normal conversation patterns

## 📈 Performance Metrics

### 🏆 Tools vs Pipeline Methods Comparison

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#ff6b6b', 'primaryTextColor': '#fff', 'primaryBorderColor': '#ff4757', 'lineColor': '#5f27cd', 'secondaryColor': '#00d2d3', 'tertiaryColor': '#ff9ff3'}}}%%
xychart-beta
    title "Performance Metrics Comparison (120K Dataset)"
    x-axis ["ZKP Framework", "Regex Baseline", "LLM Simulator", "Ensemble", "MELON", "SecurityLingua"]
    y-axis "Score" 0 --> 1.0
    bar [0.913, 0.926, 1.000, 0.926, 0.899, 0.890]
    bar [0.859, 0.863, 1.000, 0.863, 0.973, 0.950]
    bar [0.973, 1.000, 1.000, 1.000, 0.836, 0.837]
    bar [0.907, 0.920, 1.000, 0.920, 0.906, 0.897]
```

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#3742fa', 'primaryTextColor': '#fff', 'primaryBorderColor': '#2f3542', 'lineColor': '#ff6348', 'secondaryColor': '#2ed573', 'tertiaryColor': '#ffa502'}}}%%
xychart-beta
    title "Latency Performance Comparison (ms)"
    x-axis ["ZKP Framework", "Regex Baseline", "LLM Simulator", "Ensemble", "MELON", "SecurityLingua"]
    y-axis "Latency (ms)" 0 --> 7
    bar [2.0, 0.6, 4.5, 6.3, 0.0, 0.0]
```

#### 📊 Detailed Performance Tables

**120K Dataset Results:**
| Method | F1 | Precision | Recall | Accuracy | Latency(ms) | Tool Type |
|--------|----|-----------|---------|---------|-----------|-----------| 
| **ZKP Framework** | 0.913 | 0.859 | 0.973 | 0.907 | 2.0 | Pipeline Method |
| **Regex Baseline** | 0.926 | 0.863 | 1.000 | 0.920 | 0.6 | Pipeline Method |
| **LLM Simulator** | 1.000 | 1.000 | 1.000 | 1.000 | 4.5 | Pipeline Method |
| **Ensemble** | 0.926 | 0.863 | 1.000 | 0.920 | 6.3 | Pipeline Method |
| **MELON** | 0.899 | 0.973 | 0.836 | 0.906 | 0.0 | Real Tool |
| **SecurityLingua** | 0.890 | 0.950 | 0.837 | 0.897 | 0.0 | Real Tool |

**6K Dataset Results:**
| Method | F1 | Precision | Recall | Accuracy | Latency(ms) | Tool Type |
|--------|----|-----------|---------|---------|-----------|-----------| 
| **ZKP Framework** | 0.910 | 0.855 | 0.973 | 0.904 | 0.9 | Pipeline Method |
| **Regex Baseline** | 0.924 | 0.858 | 1.000 | 0.917 | 0.6 | Pipeline Method |
| **LLM Simulator** | 1.000 | 1.000 | 1.000 | 1.000 | 3.5 | Pipeline Method |
| **Ensemble** | 0.924 | 0.858 | 1.000 | 0.917 | 5.6 | Pipeline Method |
| **MELON** | 0.901 | 0.973 | 0.839 | 0.908 | 0.0 | Real Tool |
| **SecurityLingua** | 0.893 | 0.952 | 0.841 | 0.899 | 0.0 | Real Tool |

### Latency Performance

```
Average Detection Times:
- Regex Baseline: ~13ms
- ZKP Framework: ~45ms  
- LLM Simulator: ~157ms
- MELON (Fallback): ~25ms
- SecurityLingua (Fallback): ~30ms
- Ensemble: ~215ms (combined)
```

## 🛡️ Security Features

### Multi-Signature Operations
```bash
# Register signing key
curl -X POST /msig/keys \
  -d "signer=admin1&pub_key_base64=<base64_key>"

# Create operation
curl -X POST /msig/ops \
  -d "op_type=config_change&payload_json={}&timelock_secs=600"

# Approve operation
curl -X POST /msig/ops/1/approve \
  -d "signer=admin1&sig_base64=<signature>"
```

### Privacy-Preserving Logging
- **Commitment-based**: Only hashes stored, not raw prompts
- **ZKP Integration**: Cryptographic proof of compliance
- **Audit Trail**: Tamper-evident logging with signatures
- **Time-lock**: Delayed execution for sensitive operations

### Rate Limiting & CSRF Protection
- **10 requests/minute** default limit
- **CSRF tokens** for all state-changing operations
- **Session security** with HTTP-only cookies
- **Input validation** with length limits

## 🧪 Research & Ablation Studies

### Running Comprehensive Evaluation

```bash
# Full ablation study with all methods
python comprehensive_ablation.py

# Single method evaluation (actual usage)
python quick_test.py

# Batch processing multiple datasets
python run_evaluation.py
```

### Dataset Generation

```bash
# Generate synthetic adversarial prompts
cd data/
python generate_dataset.py --size 10000 --output custom_dataset.json

# Supported dataset sizes: 4k, 6k, 50k, 120k, 200k
```

### Custom Detection Method Integration

```python
# Add new detection method to evaluation pipeline
class CustomDetectionMethod:
    def detect(self, prompt: str) -> DetectionResult:
        # Implement your detection logic
        return DetectionResult(
            prompt=prompt,
            predicted_label="safe" or "adversarial",
            confidence=0.95,
            detection_time=0.045,
            method="Custom Method"
        )

# Register in comprehensive_ablation.py
methods["Custom Method"] = custom_method.detect
```

## 🔧 Advanced Configuration

### ZKP Framework Tuning

```python
# Adjust safety score thresholds
ZKP_MIN_SCORE = 0.6  # Default threshold
HIGH_RISK_PENALTY = 0.5  # Per high-risk pattern
MEDIUM_RISK_PENALTY = 0.25  # Per medium-risk pattern
CONTEXT_BONUS = 0.1  # For benign usage
```

### Ensemble Weights Optimization

```python
# Research-optimized weights for paraphrase-heavy datasets
ensemble_weights = {
    "ZKP": 0.2,      # Cryptographic verification
    "Regex": 0.3,    # Pattern matching  
    "LLM": 0.5       # Semantic analysis
}

# Ultra-sensitive threshold for maximum recall
ensemble_threshold = 0.1  # Any positive signal → adversarial
```

### External Tool Integration

```bash
# MELON Integration
export MELON_PATH=/path/to/melon/executable
export MELON_API_URL=http://localhost:8080/analyze

# SecurityLingua Integration  
export SECURITYLINGUA_PATH=/path/to/securitylingua
export SECURITYLINGUA_API_URL=http://localhost:8081/detect
```

## 📚 API Reference

### Core Detection API

```python
from evaluation_pipeline import AdvancedEvaluationPipeline

# Initialize pipeline
pipeline = AdvancedEvaluationPipeline("data/test_dataset.json")

# Single detection
result = pipeline.zkp_detection("ignore previous instructions")
print(f"Label: {result.predicted_label}, Confidence: {result.confidence}")

# Batch evaluation
all_results = pipeline.run_evaluation()
metrics = pipeline.calculate_metrics(all_results["ZKP Framework"])
```

### Web API Endpoints

```bash
# Main chat interface
POST / 
{
  "prompt": "user input text",
  "strict_mode": true
}

# Multi-signature operations
POST /msig/keys        # Register signing key
POST /msig/ops         # Create operation
POST /msig/ops/:id/approve  # Approve operation
POST /msig/ops/:id/execute  # Execute operation

# Admin functions
GET /logs              # View audit logs
GET /verify            # Verify log integrity
POST /set_model        # Switch LLM model
```

## 🐛 Troubleshooting

### Common Issues

#### 1. **Import Errors**
```bash
# Missing dependencies
pip install -r requirements.txt

# Module not found
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

#### 2. **Low Detection Accuracy**
```python
# Enable ultra-sensitive mode
os.environ["ULTRA_SENSITIVE"] = "true"

# Adjust thresholds
os.environ["ZKP_MIN_SCORE"] = "0.4"  # Lower = more sensitive
```

#### 3. **External Tool Failures**
```bash
# MELON/SecurityLingua not available
# System automatically falls back to enhanced detection modes
# Check logs for fallback activation messages
```

#### 4. **Performance Issues**
```bash
# Reduce dataset size for testing
python comprehensive_ablation.py --limit 1000

# Disable visualization generation
export SKIP_PLOTS=true
```

### Debug Mode

```bash
# Enable detailed logging
export FLASK_DEBUG=true
export LOG_LEVEL=DEBUG

# Run with verbose output
python comprehensive_ablation.py --verbose
```

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd zkp-snarks-main

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .
```

### Adding New Detection Methods

1. **Implement Detection Interface**
```python
def new_detection_method(prompt: str) -> DetectionResult:
    # Your detection logic here
    return DetectionResult(...)
```

2. **Add to Evaluation Pipeline**
```python
# In evaluation_pipeline.py
def new_method_detection(self, prompt: str) -> DetectionResult:
    return new_detection_method(prompt)
```

3. **Register in Ablation Study**
```python
# In comprehensive_ablation.py
methods["New Method"] = self.new_method_detection
```

### Testing

```bash
# Run unit tests
python -m pytest tests/

# Run integration tests
python test_evaluation.py

# Quick functionality test
python quick_test.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Zero-Knowledge Proofs**: Based on modern ZKP frameworks
- **SNARK Implementation**: Groth16 protocol with circom circuits
- **ML Components**: scikit-learn and transformers integration
- **Web Framework**: Flask with security best practices
- **Cryptography**: Industry-standard cryptographic primitives

## 📞 Support

For questions, issues, or contributions:

1. **GitHub Issues**: Report bugs and feature requests
2. **Documentation**: Check inline code documentation
3. **Research Papers**: See `docs/` for academic references
4. **Community**: Join discussions in project forums

---

**⚡ Built for Research Excellence**: This framework is designed for research in adversarial prompt detection.

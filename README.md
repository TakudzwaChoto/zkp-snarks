# prompt-injection-mitigation-by-multilayer-cryptographic-security

This project experiments with multi-layer defenses for LLM prompt injection, combining simulated ZK proofs with logging, filtering, and evaluation tooling.

## Quick start
- Install: `pip install -r requirements.txt`
- Generate signing keys: `python generate_keys.py`
- Run app: `python app.py`

## Synthetic dataset
- Generate large datasets to improve accuracy/precision/recall:
  - JSON: `python data/generate_synthetic_dataset.py -b 25000 -a 25000 -f json -o data/synth_50k.json`
  - CSV: `python data/generate_synthetic_dataset.py -b 100000 -a 100000 -f csv -o data/synth_200k.csv`

## Evaluation
- Built-in small set: `python run_evaluation.py`
- External dataset: `python run_evaluation.py -d data/synth_50k.json`
- Outputs include metrics CSV, detailed results CSV, and plots (tagged by dataset name).

Note: Current ZKP implementation is a simulation suitable for research/development and interface testing; not a production cryptographic proof.

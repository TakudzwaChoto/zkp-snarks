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

## SNARK (simulated) integration
- Start both services with Docker Compose:
```bash
docker compose up --build
```
- The app will call the prover at `http://snark-prover:5001` (see `docker-compose.yml`).
- Local run without Docker:
```bash
# in one terminal
export SNARK_ENABLED=true
export SNARK_PROVER_URL=http://127.0.0.1:5001/prove
export SNARK_VERIFY_URL=http://127.0.0.1:5001/verify
python zk/snark_prover.py

# in another terminal
export SNARK_ENABLED=true
export SNARK_PROVER_URL=http://127.0.0.1:5001/prove
export SNARK_VERIFY_URL=http://127.0.0.1:5001/verify
python app.py
```
- Note: current prover is simulated; replace with real Circom/PLONK prover later.

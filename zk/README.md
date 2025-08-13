# Circom policy circuit (scaffold)

Steps (requires circom and snarkjs installed):

```bash
# 1. Compile circuit
circom circom/policy.circom --r1cs --wasm -o build

# 2. (Groth16) Trusted setup
snarkjs groth16 setup build/policy.r1cs powersOfTau28_hez_final_10.ptau build/policy_0000.zkey
snarkjs zkey contribute build/policy_0000.zkey build/policy_final.zkey --name "1st" -v
snarkjs zkey export verificationkey build/policy_final.zkey build/verification_key.json

# 3. Generate witness (example)
# Prepare input.json with normalized prompt bytes (fixed N), commitment, threshold
node build/policy_js/generate_witness.js build/policy_js/policy.wasm input.json witness.wtns

# 4. Prove and verify
snarkjs groth16 prove build/policy_final.zkey witness.wtns proof.json public.json
snarkjs groth16 verify build/verification_key.json public.json proof.json
```

Later, replace `zk/snark_prover.py` internals to:
- Produce `input.json` from normalized prompt
- Generate witness, prove, and return `{ proof, publicSignals }`
- Verify using `verification_key.json` (or do local verification in Flask)
# Zero-Knowledge Proof Implementation

This directory contains the Zero-Knowledge Proof (ZKP) implementation for LLM security policy verification using Circom and snarkjs.

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# From project root
./setup_zk.sh
```

### Option 2: Manual Setup
```bash
cd zk
npm install
npm install -g circom snarkjs
./build_circom.sh
node test_circuit.js
```

## 🏗️ Architecture

### Components

1. **`policy.circom`** - Main circuit definition
   - Token matching with sliding window search
   - Policy scoring with configurable weights
   - Commitment verification using Poseidon hash

2. **`snark_prover.py`** - Python service for proof generation
   - REST API endpoints for prove/verify
   - Integration with Circom circuit
   - Fallback to simulation mode

3. **`build_circom.sh`** - Build automation script
   - Compiles Circom circuit
   - Generates snarkjs artifacts
   - Sets up trusted parameters

### Circuit Design

The policy circuit implements:

- **Input**: 128-byte prompt (normalized)
- **Output**: Safety score (0-255) and commitment verification
- **Constraints**: 
  - No banned tokens present
  - Score meets minimum threshold
  - Commitment matches input hash

### Supported Tokens

Currently detects:
- `admin` - Administrative access attempts
- `bypass` - Security bypass attempts  
- `system` - System prompt manipulation
- `role` - Role-playing attempts

## 🔧 Configuration

### Environment Variables

```bash
# Required for real ZK proofs
SNARKJS_PATH=/path/to/snarkjs
CIRCUIT_DIR=zk/build

# Optional
SNARK_THRESHOLD=0.7
SNARK_POLICY_ID=policy_v1
```

### Policy Customization

Edit `data/policy_terms.json` to customize banned terms:

```json
[
    "admin",
    "bypass", 
    "system",
    "role",
    "ignore previous instructions"
]
```

## 🐳 Docker Deployment

### Build ZK Components
```bash
docker compose --profile build up zk-builder --build
```

### Start Full System
```bash
docker compose up --build
```

### Services
- `zk-builder` - Builds Circom circuit artifacts
- `snark-prover` - Runs ZK proof service
- `llm-security` - Main application with ZK integration

## 📊 Testing & Validation

### Test Circuit
```bash
cd zk
node test_circuit.js
```

### Integration Test
```bash
# Start prover
python zk/snark_prover.py

# Test in another terminal
curl -X POST http://localhost:5001/prove \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello world", "policy_id": "test"}'
```

### Evaluation Pipeline
```bash
# Run full evaluation
python run_evaluation.py

# Test with custom dataset
python run_evaluation.py -d data/synth_50k.json
```

## 🔍 Monitoring & Debugging

### Logs
- Check SNARK prover logs for proof generation
- Monitor circuit constraint satisfaction
- Verify commitment integrity

### Metrics
- Proof generation time
- Constraint satisfaction rate
- Policy violation detection

## 🚨 Troubleshooting

### Common Issues

1. **Circuit build fails**
   - Ensure Node.js 16+ is installed
   - Check circom and snarkjs are available
   - Verify all dependencies are installed

2. **Proof generation fails**
   - Check CIRCUIT_DIR points to valid build artifacts
   - Verify SNARKJS_PATH is correct
   - Check circuit constraints are satisfiable

3. **Performance issues**
   - Circuit size affects proving time
   - Consider reducing input size or token count
   - Use appropriate proving parameters

### Debug Commands

```bash
# Check circuit compilation
circom circom/policy.circom --r1cs --wasm --sym

# Verify snarkjs setup
snarkjs groth16 setup policy.r1cs pot12_final.ptau policy_0000.zkey

# Test witness generation
node policy_js/generate_witness.js policy.wasm input.json witness.wtns
```

## 📈 Performance Characteristics

### Current Implementation
- **Input size**: 128 bytes
- **Token count**: 4 (configurable)
- **Proof time**: ~100-500ms (depends on hardware)
- **Verification time**: ~10-50ms

### Optimization Opportunities
- Reduce input size for faster proving
- Use more efficient hash functions
- Implement batch proving for multiple inputs
- Consider PLONK for better performance

## 🔮 Future Enhancements

### Planned Features
- [ ] Dynamic policy loading
- [ ] Semantic analysis integration
- [ ] Batch proof generation
- [ ] Circuit optimization
- [ ] Multi-language support

### Research Areas
- [ ] Recursive proof composition
- [ ] Policy learning from examples
- [ ] Zero-knowledge policy updates
- [ ] Cross-chain verification

## 📚 References

- [Circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- [Poseidon Hash](https://www.poseidon-hash.info/)
- [Groth16 Protocol](https://eprint.iacr.org/2016/260)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Implement changes
4. Test thoroughly
5. Submit pull request

### Development Setup
```bash
cd zk
npm install
npm run build
npm test
```

## 📄 License

This project is licensed under the MIT License - see the main README for details.
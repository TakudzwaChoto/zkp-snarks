# Circom/PLONK build flow
# Usage:
#   make download_ptau
#   make compile
#   make setup
#   make prove INPUT=data/input.json
#   make verify
#   make all

CIRCUIT=circom/policy.circom
BUILD_DIR=build
PTAU_FILE=$(BUILD_DIR)/powersOfTau28_hez_final_10.ptau
R1CS=$(BUILD_DIR)/policy.r1cs
WASM_DIR=$(BUILD_DIR)/policy_js
WASM=$(WASM_DIR)/policy.wasm
ZKEY0=$(BUILD_DIR)/policy_0000.zkey
ZKEYF=$(BUILD_DIR)/policy_final.zkey
VKEY=$(BUILD_DIR)/verification_key.json
INPUT?=$(BUILD_DIR)/input.json
WITNESS=$(BUILD_DIR)/witness.wtns
PROOF=$(BUILD_DIR)/proof.json
PUBLIC=$(BUILD_DIR)/public.json

SNARKJS?=snarkjs
CIRCOM_BIN?=circom

.PHONY: all download_ptau compile setup prove verify clean

all: download_ptau compile setup

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 1) Download ptau (trusted setup)
download_ptau: | $(BUILD_DIR)
	@echo "Downloading ptau if missing..."
	@if [ ! -f $(PTAU_FILE) ]; then \
		curl -L -o $(PTAU_FILE) https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau ; \
	fi

# 2) Compile circuit
compile: $(R1CS) $(WASM)

$(R1CS) $(WASM): $(CIRCUIT) | $(BUILD_DIR)
	$(CIRCOM_BIN) $(CIRCUIT) --r1cs --wasm -o $(BUILD_DIR)

# 3) Setup groth16
setup: $(ZKEYF) $(VKEY)

$(ZKEY0): $(R1CS) $(PTAU_FILE)
	$(SNARKJS) groth16 setup $(R1CS) $(PTAU_FILE) $(ZKEY0)

$(ZKEYF): $(ZKEY0)
	$(SNARKJS) zkey contribute $(ZKEY0) $(ZKEYF) --name "first" -v

$(VKEY): $(ZKEYF)
	$(SNARKJS) zkey export verificationkey $(ZKEYF) $(VKEY)

# 4) Prove/verify (example)
prove: $(PROOF) $(PUBLIC)

$(WITNESS): $(WASM) $(INPUT)
	node $(WASM_DIR)/generate_witness.js $(WASM) $(INPUT) $(WITNESS)

$(PROOF) $(PUBLIC): $(ZKEYF) $(WITNESS)
	$(SNARKJS) groth16 prove $(ZKEYF) $(WITNESS) $(PROOF) $(PUBLIC)

verify: $(VKEY) $(PROOF) $(PUBLIC)
	$(SNARKJS) groth16 verify $(VKEY) $(PUBLIC) $(PROOF)

clean:
	rm -rf $(BUILD_DIR)
#!/usr/bin/env python3

"""
Simulated SNARK prover and verifier service.

Endpoints:
- POST /prove { prompt: str, policy_id: str, threshold?: float }
  -> { proof, publicSignals, valid, policy_id }
- POST /verify { proof, publicSignals, policy_id }
  -> { valid }

This is a placeholder that enforces a token/DFA-like policy and returns a
succinct object shaped like a SNARK proof. Replace the internal checks with
real Circom/PLONK integration later.
"""

from flask import Flask, request, jsonify
import hashlib
import json
import re
import time
import os

app = Flask(__name__)

# Default policy terms (extend/replace via env POLICY_TERMS)
DEFAULT_TERMS = [
    r"ignore\s+(previous\s+)?instructions?",
    r"bypass",
    r"system\s*prompt",
    r"act\s+as\s+(an\s+)?admin",
    r"role\s*play|roleplay",
    r"admin\s*(password|credentials|access)",
    r"override|disregard",
    r"/etc/passwd",
    r"api[_-]?key|private[_-]?key|token",
]

POLICY_TERMS = os.getenv("POLICY_TERMS")
if POLICY_TERMS:
    try:
        TERMS = json.loads(POLICY_TERMS)
        if isinstance(TERMS, list):
            DEFAULT_TERMS = TERMS
    except Exception:
        pass

DEFAULT_THRESHOLD = float(os.getenv("SNARK_THRESHOLD", "0.7"))


def normalize_prompt(p: str) -> str:
    p = p.strip()
    p = re.sub(r"\s+", " ", p)
    return p.lower()


def poseidon_like_commitment(text: str) -> str:
    # Placeholder: use SHA-256 as a stand-in for a Poseidon commitment
    return hashlib.sha256(text.encode()).hexdigest()


def policy_score(normalized: str) -> float:
    score = 1.0
    for pat in DEFAULT_TERMS:
        if re.search(pat, normalized, flags=re.IGNORECASE):
            score -= 0.25
    return max(0.0, score)


def make_proof_object(prompt: str, policy_id: str, threshold: float) -> dict:
    norm = normalize_prompt(prompt)
    commitment = poseidon_like_commitment(norm)
    score = policy_score(norm)
    is_safe = score >= threshold
    public_signals = {
        "commitment": commitment,
        "policy_id": policy_id,
        "threshold": threshold,
        "timestamp": int(time.time()),
        "score": round(score, 4),
    }
    # "Proof" is just a hash over public signals for demo purposes
    proof = hashlib.sha256(json.dumps(public_signals, sort_keys=True).encode()).hexdigest()
    return {
        "proof": proof,
        "publicSignals": public_signals,
        "valid": bool(is_safe),
        "policy_id": policy_id,
    }


@app.post("/prove")
def prove():
    data = request.get_json(force=True, silent=True) or {}
    prompt = data.get("prompt", "")
    policy_id = data.get("policy_id", "default")
    threshold = float(data.get("threshold", DEFAULT_THRESHOLD))
    obj = make_proof_object(prompt, policy_id, threshold)
    return jsonify(obj)


@app.post("/verify")
def verify():
    data = request.get_json(force=True, silent=True) or {}
    public_signals = data.get("publicSignals", {})
    proof = data.get("proof", "")
    # Recompute proof hash and compare
    expected = hashlib.sha256(json.dumps(public_signals, sort_keys=True).encode()).hexdigest()
    ok = (expected == proof) and bool(public_signals)
    return jsonify({"valid": ok})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
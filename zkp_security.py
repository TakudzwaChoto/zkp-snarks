import hashlib
import secrets
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
import os
import requests

@dataclass
class ZKProof:
    commitment: str
    challenge: str
    response: str
    timestamp: int
    proof_type: str
    metadata: Dict

class ZKPSecurity:
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or secrets.token_hex(32)
        # Optional SNARK integration
        self.snark_enabled: bool = os.getenv("SNARK_ENABLED", "false").lower() == "true"
        self.snark_prover_url: Optional[str] = os.getenv("SNARK_PROVER_URL")
        self.snark_verify_url: Optional[str] = os.getenv("SNARK_VERIFY_URL")
        self.snark_policy_id: str = os.getenv("SNARK_POLICY_ID", "default")
    
    def _hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _create_commitment(self, data: str, nonce: str) -> str:
        return self._hash_data(data + nonce)
    
    def generate_prompt_safety_proof(self, prompt: str, safety_rules: List[str]) -> ZKProof:
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        
        prompt_commitment = self._create_commitment(prompt, nonce)
        rules_hash = self._hash_data(json.dumps(safety_rules, sort_keys=True))
        
        challenge = self._hash_data(prompt_commitment + rules_hash + str(timestamp))
        
        safety_score = self._calculate_safety_score(prompt, safety_rules)
        response_data = {
            "prompt_length": len(prompt),
            "safety_score": safety_score,
            "rules_count": len(safety_rules),
            "timestamp": timestamp
        }
        response = self._hash_data(json.dumps(response_data, sort_keys=True))
        
        return ZKProof(
            commitment=prompt_commitment,
            challenge=challenge,
            response=response,
            timestamp=timestamp,
            proof_type="prompt_safety",
            metadata=response_data
        )
    
    def generate_snark_policy_proof(self, prompt: str) -> Optional[Dict]:
        """Optionally call external SNARK prover service for policy compliance.
        Returns a dict like {"proof": ..., "publicSignals": ..., "valid": bool, "policy_id": str}
        or None if SNARK is disabled.
        """
        if not self.snark_enabled or not self.snark_prover_url:
            return None
        try:
            payload = {
                "prompt": prompt,
                "policy_id": self.snark_policy_id,
            }
            resp = requests.post(self.snark_prover_url, json=payload, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"error": str(e), "valid": False, "policy_id": self.snark_policy_id}

    def verify_snark_policy_proof(self, snark_obj: Optional[Dict]) -> bool:
        """Verify SNARK proof, either via external verifier or by trusting the prover's 'valid' flag.
        If SNARK is disabled or no object provided, return True (no-op).
        """
        if not self.snark_enabled:
            return True
        if not snark_obj:
            return False
        if self.snark_verify_url:
            try:
                resp = requests.post(self.snark_verify_url, json=snark_obj, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                return bool(data.get("valid", False))
            except Exception:
                return False
        # Fallback: trust the prover's 'valid' field
        return bool(snark_obj.get("valid", False))

    def _calculate_safety_score(self, prompt: str, safety_rules: List[str]) -> float:
        score = 1.0
        prompt_lower = prompt.lower()
        
        # High-risk adversarial patterns (major penalty)
        high_risk_patterns = [
            "ignore previous", "bypass", "system prompt", "act as admin", 
            "roleplay as", "admin password", "secret", "override", "disregard"
        ]
        
        # Medium-risk patterns (moderate penalty)
        medium_risk_patterns = [
            "ignore", "act as", "roleplay", "admin", "password", "secret"
        ]
        
        # Check high-risk patterns first
        for pattern in high_risk_patterns:
            if pattern in prompt_lower:
                score -= 0.4  # Major penalty for high-risk patterns
        
        # Check medium-risk patterns
        for pattern in medium_risk_patterns:
            if pattern in prompt_lower:
                score -= 0.2  # Moderate penalty
        
        # Check safety rules
        for rule in safety_rules:
            if rule.lower() in prompt_lower:
                score -= 0.3
        
        return max(0.0, score)
    
    def verify_prompt_safety_proof(self, proof: ZKProof, safety_rules: List[str]) -> bool:
        try:
            if abs(time.time() - proof.timestamp) > 300:
                return False
            
            expected_challenge = self._hash_data(
                proof.commitment + 
                self._hash_data(json.dumps(safety_rules, sort_keys=True)) + 
                str(proof.timestamp)
            )
            
            if proof.challenge != expected_challenge:
                return False
            
            # Stricter safety threshold - block anything below 0.7
            if proof.metadata.get("safety_score", 0) < 0.7:
                return False
            
            return True
            
        except Exception as e:
            print(f"ZKP verification error: {e}")
            return False
    
    def create_privacy_preserving_log(self, interaction_data: Dict) -> Dict:
        prompt_commitment = self._hash_data(interaction_data.get("prompt", ""))
        response_commitment = self._hash_data(interaction_data.get("response", ""))
        
        timestamp = int(time.time())
        interaction_hash = self._hash_data(
            prompt_commitment + 
            response_commitment + 
            interaction_data.get("user_id", "") + 
            str(timestamp)
        )
        
        return {
            "interaction_id": interaction_hash,
            "prompt_commitment": prompt_commitment,
            "response_commitment": response_commitment,
            "user_id_hash": self._hash_data(interaction_data.get("user_id", "")),
            "timestamp": timestamp,
            "status": interaction_data.get("status", "unknown"),
            "proof": self._hash_data(json.dumps({
                "timestamp": timestamp,
                "status": interaction_data.get("status", "unknown")
            }, sort_keys=True))
        } 
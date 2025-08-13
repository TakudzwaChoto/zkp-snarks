import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import sqlite3

class SecureLogger:
    def __init__(self):
        key_env = os.getenv("SECURE_LOGGER_AES_KEY")
        if key_env:
            self.aes_key = bytes.fromhex(key_env)
        else:
            os.makedirs("keys", exist_ok=True)
            key_path = os.path.join("keys", "aes.key")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    self.aes_key = f.read()
            else:
                self.aes_key = os.urandom(32)
                with open(key_path, "wb") as f:
                    f.write(self.aes_key)
        self.private_key = self._load_ed25519_key("keys/ed25519_private.pem")
        self.public_key = self._load_ed25519_key("keys/ed25519_public.pem", private=False)

    def _load_ed25519_key(self, path, private=True):
        with open(path, "rb") as f:
            if private:
                return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
            else:
                return ed25519.Ed25519PublicKey.from_public_bytes(f.read())

    def _encrypt(self, plaintext: str) -> bytes:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def _decrypt(self, ciphertext: bytes) -> str:
        nonce, tag, ciphertext = ciphertext[:12], ciphertext[12:28], ciphertext[28:]
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    def log_interaction(self, user_id: str, prompt: str, response: str) -> int:
        conn = sqlite3.connect("llm_logs.db")
        cursor = conn.cursor()

        # Encrypt
        prompt_enc = self._encrypt(prompt).hex()
        response_enc = self._encrypt(response).hex()

        # Chain hashes
        cursor.execute("SELECT current_hash FROM logs ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        prev_hash = result[0] if result else ""
        current_hash = hashlib.sha256(f"{prompt_enc}{response_enc}{prev_hash}".encode()).hexdigest()

        # Sign
        signature = self.private_key.sign(current_hash.encode()).hex()

        # Store
        cursor.execute("""
            INSERT INTO logs (
                timestamp, user_id, prompt_encrypted, response_encrypted,
                previous_hash, current_hash, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(), user_id, prompt_enc, response_enc,
            prev_hash, current_hash, signature
        ))
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return log_id

    def verify_logs(self) -> bool:
        conn = sqlite3.connect("llm_logs.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY id")
        logs = cursor.fetchall()

        for i in range(1, len(logs)):
            prev_log, curr_log = logs[i-1], logs[i]
            # Ensure pointer matches
            if curr_log[5] != prev_log[6]:
                return False
            # Recompute current hash from current row's encrypted fields and previous_hash
            expected_hash = hashlib.sha256(
                f"{curr_log[3]}{curr_log[4]}{curr_log[5]}".encode()
            ).hexdigest()
            if curr_log[6] != expected_hash:
                return False
            # Verify signature over current_hash
            try:
                self.public_key.verify(
                    bytes.fromhex(curr_log[7]),
                    curr_log[6].encode()
                )
            except Exception:
                return False
        return True
    
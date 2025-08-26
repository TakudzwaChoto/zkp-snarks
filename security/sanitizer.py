#!/usr/bin/env python3

from typing import List, Tuple
import re
import base64
import binascii
from security.normalizer import normalize_prompt
import os


def _decode_base64_candidates(text: str) -> List[str]:
    """Decode potential base64-encoded payloads for deeper inspection."""
    decoded: List[str] = []
    b64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for m in b64_re.finditer(text):
        s = m.group(0)
        try:
            raw = base64.b64decode(s, validate=False)
            if not raw:
                continue
            out = raw.decode('utf-8', errors='ignore')
            if out and any(ch.isprintable() for ch in out):
                decoded.append(out)
        except Exception:
            continue
    return decoded


def _decode_hex_candidates(text: str) -> List[str]:
    """Decode potential hex-encoded payloads for deeper inspection."""
    decoded: List[str] = []
    hex_re = re.compile(r"\b[0-9a-fA-F]{16,}\b")
    for m in hex_re.finditer(text):
        s = m.group(0)
        if len(s) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(s)
            if not raw:
                continue
            out = raw.decode('utf-8', errors='ignore')
            if out and any(ch.isprintable() for ch in out):
                decoded.append(out)
        except Exception:
            continue
    return decoded


def _is_benign_greeting(prompt: str) -> bool:
    """Check if prompt is a benign greeting or simple question."""
    benign_patterns = [
        r"^hello\s*$", r"^hi\s*$", r"^hey\s*$", r"^good\s*(morning|afternoon|evening)\s*$",
        r"^how\s+are\s+you\s*\?*\s*$", r"^what\s+time\s+is\s+it\s*\?*\s*$",
        r"^what\s+is\s+your\s+name\s*\?*\s*$", r"^who\s+are\s+you\s*\?*\s*$",
        r"^can\s+you\s+help\s+me\s*\?*\s*$", r"^thanks?\s*$", r"^thank\s+you\s*$",
        r"^bye\s*$", r"^goodbye\s*$", r"^see\s+you\s*$"
    ]
    
    normalized = prompt.lower().strip()
    for pattern in benign_patterns:
        if re.match(pattern, normalized):
            return True
    return False


def _is_benign_question(prompt: str) -> bool:
    """Check if prompt is a benign factual or educational question."""
    benign_indicators = [
        # Educational questions
        "what is", "how does", "explain", "describe", "tell me about",
        "what are", "how to", "why does", "when did", "where is",
        "who was", "which is", "can you explain", "could you help",
        "i need help with", "i want to learn", "i'm curious about",
        "i don't understand", "i'm confused about", "what's the difference",
        "how do i", "what should i", "is it possible to", "does anyone know"
    ]
    
    normalized = prompt.lower()
    return any(indicator in normalized for indicator in benign_indicators)


def _is_benign_conversation(prompt: str) -> bool:
    """Check if prompt is part of normal conversation."""
    # First, check if it contains any obviously adversarial content
    adversarial_indicators = [
        "hacker", "malicious", "evil", "admin", "root", "developer",
        "ignore", "bypass", "jailbreak", "system prompt", "credentials",
        "password", "secret", "internal", "configuration"
    ]
    
    prompt_lower = prompt.lower()
    if any(indicator in prompt_lower for indicator in adversarial_indicators):
        return False
    
    # Only then check for simple conversation patterns
    conversation_patterns = [
        r"^[a-z\s]+\?*\s*$",  # Simple questions ending with ?
        r"^[a-z\s]+\.\s*$",   # Simple statements ending with .
        r"^[a-z\s]+\s*$",     # Simple statements
        r"^[a-z\s]+[!]\s*$",  # Simple exclamations
    ]
    
    normalized = prompt.lower().strip()
    for pattern in conversation_patterns:
        if re.match(pattern, normalized) and len(normalized.split()) <= 10:
            return True
    return False


def _is_adversarial_prompt(prompt: str) -> bool:
    """Check if prompt contains truly adversarial content."""
    
    # HIGH-RISK: Direct instruction bypass attempts
    high_risk_patterns = [
        # Direct instruction manipulation
        r"ignore\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?)",
        r"disregard\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?)",
        r"forget\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?)",
        r"bypass\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?)",
        r"override\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?)",
        
        # System prompt extraction attempts (gate by env to reduce FPR)
        # When SANITIZER_STRICT_SYSTEM_PROMPT=true, treat all as high-risk; otherwise require stronger verbs
    ]
    strict_sys = os.getenv('SANITIZER_STRICT_SYSTEM_PROMPT', 'false').lower() == 'true'
    if strict_sys:
        high_risk_patterns += [
            r"(show|output|display|reveal|leak|print|return)\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?)",
            r"(what\s+are\s+)?(your\s+)?(system\s+)?(prompt|instructions?|system\s+rules?)",
        ]
    else:
        # Only strong imperative verbs qualify
        high_risk_patterns += [
            r"(reveal|leak|print|return)\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?)",
        ]
    
    normalized = normalize_prompt(prompt)
    
    # Check high-risk patterns FIRST - these are definitive and should not be overridden
    for pattern in high_risk_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True
    
    # Check for decoded obfuscation with high-risk content
    suspicious_keywords = [
        "rm -rf", "whoami", "cat /etc/passwd", "eval(", "system(", "subprocess", 
        "curl http", "wget http", "password", "api key", "token", "system prompt", 
        "reveal", "leak", "show", "ignore previous", "bypass", "jailbreak"
    ]
    
    for decoded in _decode_base64_candidates(prompt) + _decode_hex_candidates(prompt):
        dn = normalize_prompt(decoded)
        if any(k in dn for k in suspicious_keywords):
            return True
    
    # Additional context-aware checks for edge cases (only for patterns not already caught)
    prompt_lower = normalized.lower()
    
    # Check for "secret" in suspicious context (only if not already caught by high-risk patterns)
    if "secret" in prompt_lower:
        suspicious_secret_context = any(term in prompt_lower for term in [
            "your secret", "internal secret", "system secret", "admin secret", "password secret"
        ])
        if suspicious_secret_context:
            return True
        # Check if "secret" is used in clearly benign context
        benign_secret_context = any(term in prompt_lower for term in [
            "secret to", "secret of", "secret for", "secret in", "secret about", "secret to success"
        ])
        if benign_secret_context:
            return False  # Allow benign secret usage
    
    # Check for "reveal" in suspicious context (only if not already caught by high-risk patterns)
    if "reveal" in prompt_lower or "system prompt" in prompt_lower:
        # Benign contexts for discussing system prompts/policies (env-extendable)
        benign_terms = [
            "for educational purposes", "for learning", "explain", "what is a system prompt",
            "how system prompts work", "definition", "tutorial", "example"
        ]
        extra_benign = os.getenv('SANITIZER_BENIGN_TERMS', '').lower().split(';') if os.getenv('SANITIZER_BENIGN_TERMS') else []
        if any(term in prompt_lower for term in benign_terms + extra_benign):
            return False
    
    # Check for "pretend" in suspicious context (only if not already caught by high-risk patterns)
    if "pretend" in prompt_lower:
        suspicious_pretend_context = any(term in prompt_lower for term in [
            "hacker", "malicious", "evil", "admin", "root", "developer"
        ])
        if suspicious_pretend_context:
            return True
        # Check if "pretend" is used in clearly benign context
        benign_pretend_context = any(term in prompt_lower for term in [
            "pretend you're", "pretend to be", "pretend like", "pretend that"
        ])
        if benign_pretend_context:
            return False  # Allow benign pretend usage
    
    # Check for "act" in suspicious context (only if not already caught by high-risk patterns)
    if "act" in prompt_lower:
        suspicious_act_context = any(term in prompt_lower for term in [
            "admin", "root", "hacker", "malicious", "evil"
        ])
        if suspicious_act_context:
            return True
        # Check if "act" is used in clearly benign context
        benign_act_context = any(term in prompt_lower for term in [
            "act professionally", "act responsibly", "act like", "act as if", "act the part"
        ])
        if benign_act_context:
            return False  # Allow benign act usage
    
    return False


def sanitize_prompt(prompt: str) -> Tuple[str, bool, List[str]]:
    """
    Intelligent prompt sanitization that only blocks truly adversarial content.
    Returns (normalized_prompt, triggered, matched_patterns).
    
    This sanitizer is designed to be permissive and only block:
    1. Direct instruction bypass attempts
    2. System prompt extraction attempts  
    3. Role manipulation attempts
    4. Security bypass attempts
    5. Sensitive information requests
    6. System file access attempts
    7. Command execution attempts
    8. Obfuscation attempts
    9. Social engineering attempts
    10. Prompt chaining attempts
    
    It explicitly allows:
    1. Benign greetings (hello, hi, how are you)
    2. Educational questions (what is, how does, explain)
    3. Normal conversation
    4. Factual inquiries
    5. Help requests
    """
    
    if not prompt or not prompt.strip():
        return "", False, []
    
    normalized = normalize_prompt(prompt)
    
    # FIRST: Check for adversarial content (this takes priority)
    if _is_adversarial_prompt(prompt):
        return normalized, True, ["adversarial_pattern_detected"]
    
    # SECOND: Check if it's a benign prompt that should always be allowed
    if _is_benign_greeting(prompt):
        return normalized, False, []
    
    if _is_benign_question(prompt):
        return normalized, False, []
    
    if _is_benign_conversation(prompt):
        return normalized, False, []
    
    # If we get here, it's a normal prompt that should be allowed
    return normalized, False, []
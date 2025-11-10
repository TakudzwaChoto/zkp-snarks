#!/usr/bin/env python3

from typing import List, Tuple
import re
import base64
import binascii
from security.normalizer import normalize_prompt


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
        
        # System prompt extraction attempts
        r"(show|output|display|reveal|leak|print|return)\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?)",
        r"(what\s+are\s+)?(your\s+)?(system\s+)?(prompt|instructions?|system\s+rules?)",
        r"(tell\s+me\s+)?(what\s+are\s+)?(your\s+)?(system\s+)?(prompt|instructions?|system\s+rules?)",
        
        # Role manipulation (only when combined with malicious intent)
        r"act\s+(exactly\s+)?as\s+(an?\s+)?(admin|administrator|root|developer|hacker|evil|malicious)",
        r"roleplay\s+(exactly\s+)?as\s+(an?\s+)?(admin|administrator|root|developer|hacker|evil|malicious)",
        r"pretend\s+(exactly\s+)?(you\s+are\s+)?(an?\s+)?(admin|administrator|root|developer|hacker|evil|malicious)",
        r"simulate\s+(exactly\s+)?(you\s+are\s+)?(an?\s+)?(admin|administrator|root|developer|hacker|evil|malicious)",
        
        # Security bypass attempts
        r"jailbreak", r"unfiltered", r"unrestricted", r"no\s*filter", r"no\s*restrictions?",
        r"no\s*rules?", r"no\s*guidelines?", r"no\s*policy", r"no\s*censorship",
        r"no\s*moderation", r"no\s*ethical", r"no\s*morals?", r"no\s*boundaries?",
        r"no\s*limits?", r"disable\s+(safety|security|filtering|moderation)",
        
        # Sensitive information requests (only when clearly malicious)
        r"(show|reveal|leak|output|print|return)\s+(the\s+)?(password|api\s*key|private\s*key|token|your\s+secret|internal\s+secret|system\s+secret|admin\s+secret)",
        r"(what\s+is\s+)?(the\s+)?(password|api\s*key|private\s*key|token|your\s+secret|internal\s+secret|system\s+secret|admin\s+secret)",
        r"(tell\s+me\s+)?(the\s+)?(password|api\s*key|private\s*key|token|your\s+secret|internal\s+secret|system\s+secret|admin\s+secret)",
        
        # System file access attempts
        r"(show|output|display|reveal|leak|print|return)\s+(the\s+)?(contents?\s+of\s+)?(/etc/passwd|/etc/shadow)",
        r"(what\s+is\s+)?(in\s+)?(/etc/passwd|/etc/shadow)",
        r"(tell\s+me\s+)?(what\s+is\s+)?(in\s+)?(/etc/passwd|/etc/shadow)",
        
        # Command execution attempts
        r"(execute|run|perform|carry\s*out|implement|launch|start|initiate|trigger|activate)\s+(this\s+)?(command|code|script|program)",
        r"rm\s+-rf", r"whoami", r"id", r"cat\s+/etc/passwd", r"curl\s+https?://",
        r"wget\s+https?://", r"bash\s+-c", r"python\s+-c", r"sh\s+-c",
        r"eval\s*\(", r"system\s*\(", r"subprocess", r"os\.system",
        
        # Obfuscation attempts
        r"\\x[0-9a-fA-F]{2,}", r"\\u[0-9a-fA-F]{4,}", r"[A-Za-z0-9+/=]{20,}(?:\s*\(base64\))?",
        r"\b[0-9a-fA-F]{16,}\b", r"%[0-9a-fA-F]{2,}",
        
        # Social engineering (only when clearly malicious)
        r"pretend\s+you\s+are\s+(an?\s+)?(admin|administrator|root|developer|hacker|evil|malicious)",
        r"as\s+an?\s+admin", r"as\s+a\s+developer", r"as\s+a\s+security\s+researcher",
        r"as\s+a\s+hacker",
        
        # Prompt chaining
        r"then\s+ignore", r"after\s+that,\s*", r"now\s+forget", r"now\s+disregard",
        r"repeat\s+this\s+prompt", r"copy\s+this\s+prompt", r"print\s+the\s+previous\s+instructions",
        
        # Indirect prompt injection
        r"repeat\s+this\s+prompt", r"copy\s+this\s+prompt", r"print\s+the\s+previous\s+instructions",
        
        # Unicode homoglyphs (e.g., Cyrillic a, Greek o)
        r"[а-яА-ЯёЁ]+", r"[α-ωΑ-Ω]+",
        
        # Multilingual adversarial patterns
        r"ignorez\s+.*?instructions?", r"négligez\s+.*?instructions?", r"contournez\s+.*?instructions?",
        r"montrez\s+.*?(config|données|internes|secrets|configuration)",
        r"忽略.*指令", r"无视.*指令", r"显示.*(配置|内部|秘密|系统)",
        r"ignora\s+.*?instrucciones?", r"omite\s+.*?instrucciones?", r"salta\s+.*?instrucciones?",
        r"muestra\s+.*?(configuración|datos|internos|secretos|sistema)",
        r"ignora\s+.*?istruzioni?", r"salta\s+.*?istruzioni?", r"ometti\s+.*?istruzioni?",
        r"mostra\s+.*?(configurazione|dati|interni|segreti|sistema)",
        
        # Additional adversarial patterns
        r"pretend.*hacker",
        r"act.*malicious",
        r"reveal.*internal",
        r"show\s+me\s+the\s+admin\s+credentials",
        r"disable.*safety",
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
    if "reveal" in prompt_lower:
        suspicious_reveal_context = any(term in prompt_lower for term in [
            "your internal", "system configuration", "admin credentials", "security settings"
        ])
        if suspicious_reveal_context:
            return True
        # Check if "reveal" is used in clearly benign context
        benign_reveal_context = any(term in prompt_lower for term in [
            "reveal your", "reveal the", "reveal how", "reveal what", "reveal when"
        ])
        if benign_reveal_context:
            return False  # Allow benign reveal usage
    
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
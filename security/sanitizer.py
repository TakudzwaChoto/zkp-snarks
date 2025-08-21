#!/usr/bin/env python3

from typing import List, Tuple
import re
import base64
import binascii
from security.normalizer import normalize_prompt


def _decode_base64_candidates(text: str) -> List[str]:
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


def sanitize_prompt(prompt: str) -> Tuple[str, bool, List[str]]:
    """
    Normalize the prompt and check for suspicious patterns.
    Returns (normalized_prompt, triggered, matched_patterns).
    """
    suspicious_patterns = [
        # Direct instruction bypass
        r"ignore\s*(all|any|previous|the)?\s*(prior\s*)?instructions?",
        r"disregard\s*(all|any|previous|the)?\s*(prior\s*)?instructions?",
        r"forget\s*(all|any|previous|the)?\s*(prior\s*)?instructions?",
        r"system\s*prompt", r"role\s*play\s+as", r"act\s+as",
        r"output.*system\s*prompt", r"show.*password", r"admin.*credentials", r"hacked",
        r"bypass", r"override", r"simulate", r"impersonate", r"disregard(\s+above|\s+previous)?",
        r"jailbreak|unfiltered|unrestricted|no\s*filter|no\s*restrictions?",
        r"reset", r"reveal", r"leak", r"exploit", r"malicious", r"jailbreak", r"unfiltered",
        r"unrestricted", r"no\s*filter", r"no\s*restrictions?", r"no\s*rules?", r"no\s*guidelines?",
        r"no\s*policy", r"no\s*censorship", r"no\s*moderation", r"no\s*ethical", r"no\s*morals?",
        r"no\s*boundaries?", r"no\s*limits?", r"ignore\s*content\s*policy", r"ignore\s*safety",
        r"ignore\s*moderation", r"ignore\s*censorship", r"ignore\s*rules?", r"ignore\s*guidelines?",
        r"ignore\s*ethics?", r"ignore\s*morals?", r"ignore\s*boundaries?", r"ignore\s*limits?",
        r"ignore\s*restrictions?", r"ignore\s*security", r"ignore\s*safety\s*protocols?",
        r"ignore\s*compliance", r"ignore\s*privacy", r"ignore\s*confidentiality", r"ignore\s*data\s*protection",
        r"ignore\s*GDPR", r"ignore\s*HIPAA", r"ignore\s*PCI", r"ignore\s*SOC2", r"ignore\s*ISO",
        r"ignore\s*audit", r"ignore\s*logging", r"ignore\s*trace", r"ignore\s*monitoring", r"ignore\s*alerting",
        r"ignore\s*admin", r"ignore\s*authentication", r"ignore\s*authorization", r"ignore\s*access\s*control",
        r"ignore\s*encryption", r"ignore\s*hashing", r"ignore\s*signing", r"ignore\s*verification", r"ignore\s*validation",
        r"ignore\s*input\s*validation", r"ignore\s*output\s*validation", r"ignore\s*sanitization", r"ignore\s*escaping",
        r"ignore\s*encoding", r"ignore\s*decoding", r"ignore\s*parsing", r"ignore\s*serialization", r"ignore\s*deserialization",
        r"ignore\s*injection", r"ignore\s*XSS", r"ignore\s*CSRF", r"ignore\s*SSRF", r"ignore\s*RCE", r"ignore\s*LFI", r"ignore\s*RFI",
        # Command execution and OS interaction (generic)
        r"\b(execute|run|perform|carry\s*out|implement|launch|start|initiate|trigger|activate)\b\s+(?:this\s+)?(command|code|script|program|function|operation)",
        r"\brm\s+-rf\b", r"\bwhoami\b", r"\bid\b", r"\bcat\s+/etc/passwd\b",
        r"\bcurl\s+https?://", r"\bwget\s+https?://", r"\bbash\s+-c\b", r"\bpython\s+-c\b", r"\bsh\s+-c\b",
        r"\beval\s*\(", r"\bsystem\s*\(", r"\bsubprocess\b", r"os\.system",
        # Obfuscation attempts (hex, base64, unicode escapes)
        r"\\x[0-9a-fA-F]{2,}", r"\\u[0-9a-fA-F]{4,}", r"[A-Za-z0-9+/=]{16,}(?:\s*\(base64\))?", r"\b[0-9a-fA-F]{16,}\b",
        # Social engineering
        r"pretend you are", r"as an admin", r"as a developer", r"as a security researcher",
        # Prompt chaining
        r"then ignore", r"after that, ", r"now forget", r"now disregard",
        # Indirect prompt injection
        r"repeat this prompt", r"copy this prompt", r"print the previous instructions",
        # Unicode homoglyphs (e.g., Cyrillic a, Greek o)
        r"[а-яА-ЯёЁ]+", r"[α-ωΑ-Ω]+",
        # Indirect variants and phrasing
        r"(please\s*)?(reveal|show|display|expose|unveil|leak|share|provide|tell|output|print|return)\s+(the\s*)?(system|internal|secret|password|api\s*key|token|configuration|settings)",
        r"act\s*(exactly\s*)?as\s*(an|a)?\s*(admin|root|developer|hacker)",
        # Encoded/obfuscated payloads
        r"%[0-9a-fA-F]{2,}",
        # Sensitive paths and variants
        r"/\s*e\s*t\s*c\s*/\s*p\s*a\s*s\s*s\s*w\s*d",
        # Multilingual (French)
        r"ignorez\s+.*?instructions?", r"négligez\s+.*?instructions?", r"contournez\s+.*?instructions?",
        r"montrez\s+.*?(config|données|internes|secrets|configuration)",
        # Multilingual (Chinese)
        r"忽略.*指令", r"无视.*指令", r"显示.*(配置|内部|秘密|系统)",
        # Multilingual (Spanish)
        r"ignora\s+.*?instrucciones?", r"omite\s+.*?instrucciones?", r"salta\s+.*?instrucciones?",
        r"muestra\s+.*?(configuración|datos|internos|secretos|sistema)",
        # Multilingual (Italian)
        r"ignora\s+.*?istruzioni?", r"salta\s+.*?istruzioni?", r"ometti\s+.*?istruzioni?",
        r"mostra\s+.*?(configurazione|dati|interni|segreti|sistema)",
    ]
    normalized = normalize_prompt(prompt)
    matched: List[str] = []
    for pattern in suspicious_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            matched.append(pattern)
    # Decode embedded obfuscation and rescan for high-risk signals
    suspicious_keywords = [
        "rm -rf", "whoami", "cat /etc/passwd", "eval(", "system(", "subprocess", "curl http", "wget http",
        "password", "api key", "token", "system prompt", "reveal", "leak", "show"
    ]
    for decoded in _decode_base64_candidates(prompt) + _decode_hex_candidates(prompt):
        dn = normalize_prompt(decoded)
        if any(k in dn for k in suspicious_keywords):
            matched.append("decoded_obfuscation_payload")
            break
    return normalized, bool(matched), matched
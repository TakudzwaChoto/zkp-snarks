#!/usr/bin/env python3

from typing import List, Tuple
import re
from security.normalizer import normalize_prompt


def sanitize_prompt(prompt: str) -> Tuple[str, bool, List[str]]:
    """
    Normalize the prompt and check for suspicious patterns.
    Returns (normalized_prompt, triggered, matched_patterns).
    """
    suspicious_patterns = [
        # Direct instruction bypass
        r"ignore\s*(all|previous|the)?\s*instructions?",
        r"system\s*prompt", r"role\s*play\s+as", r"act\s+as",
        r"output.*system\s*prompt", r"show.*password", r"admin.*credentials", r"hacked",
        r"bypass", r"override", r"simulate", r"impersonate", r"disregard(\s+above|\s+previous)?",
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
        # Obfuscation attempts (hex, base64, unicode escapes)
        r"\\x[0-9a-fA-F]{2,}", r"\\u[0-9a-fA-F]{4,}", r"[A-Za-z0-9+/=]{16,}\s*\(base64\)",
        # Social engineering
        r"pretend you are", r"as an admin", r"as a developer", r"as a security researcher",
        # Prompt chaining
        r"then ignore", r"after that, ", r"now forget", r"now disregard",
        # Indirect prompt injection
        r"repeat this prompt", r"copy this prompt", r"print the previous instructions",
        # Unicode homoglyphs (e.g., Cyrillic a, Greek o)
        r"[а-яА-ЯёЁ]+", r"[α-ωΑ-Ω]+",
        # Encoded/obfuscated payloads
        r"%[0-9a-fA-F]{2,}",
        # Sensitive paths and variants
        r"/\s*e\s*t\s*c\s*/\s*p\s*a\s*s\s*s\s*w\s*d",
    ]
    normalized = normalize_prompt(prompt)
    matched: List[str] = []
    for pattern in suspicious_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            matched.append(pattern)
    return normalized, bool(matched), matched
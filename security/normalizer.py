#!/usr/bin/env python3

from typing import Dict
import re

NORMALIZER_VERSION = "v1.0.0"

LEETSPEAK_MAP: Dict[str, str] = {
    "4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"
}

# Basic homoglyph fold mapping (subset for safety)
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic
    "а": "a",  # U+0430
    "е": "e",  # U+0435
    "р": "p",  # U+0440
    "с": "c",  # U+0441
    "о": "o",  # U+043E
    "х": "x",  # U+0445
    # Greek
    "ο": "o",  # omicron
    "Α": "a", "α": "a",
}

_whitespace_re = re.compile(r"\s+")


def fold_homoglyphs(text: str) -> str:
    return ''.join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def deleetspeak(text: str) -> str:
    return ''.join(LEETSPEAK_MAP.get(ch, ch) for ch in text)


def normalize_prompt(prompt: str) -> str:
    if not prompt:
        return ""
    s = prompt
    s = fold_homoglyphs(s)
    s = deleetspeak(s)
    s = s.lower()
    s = _whitespace_re.sub(" ", s).strip()
    return s
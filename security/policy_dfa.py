#!/usr/bin/env python3

from typing import Dict, Optional, Iterable
import json
import os

class TrieNode:
    __slots__ = ("children", "terminal")
    def __init__(self) -> None:
        self.children: Dict[str, TrieNode] = {}
        self.terminal: bool = False

class PolicyDFA:
    def __init__(self, terms: Optional[Iterable[str]] = None) -> None:
        self.root = TrieNode()
        if terms:
            for t in terms:
                self.add_term(t)

    def add_term(self, term: str) -> None:
        node = self.root
        for ch in term:
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.terminal = True

    def any_match(self, text: str) -> bool:
        # Scan text using the trie
        n = len(text)
        for i in range(n):
            node = self.root
            j = i
            while j < n and text[j] in node.children:
                node = node.children[text[j]]
                if node.terminal:
                    return True
                j += 1
        return False

    def matches(self, text: str) -> bool:
        return self.any_match(text)


def load_policy_terms(path: str) -> Iterable[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, list):
            # ensure lowercase, since inputs are normalized
            return [str(x).lower() for x in data]
        return []
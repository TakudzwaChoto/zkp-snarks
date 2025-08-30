#!/usr/bin/env python3

from typing import List, Tuple, Dict
from dataclasses import dataclass

try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.linear_model import LogisticRegression  # type: ignore
    from sklearn.pipeline import Pipeline  # type: ignore
    from sklearn.metrics import classification_report  # type: ignore
except Exception:
    TfidfVectorizer = None
    LogisticRegression = None
    Pipeline = None
    classification_report = None

import os
import math
import re
from typing import Iterable
try:
    import numpy as np  # type: ignore
except Exception:
    np = None

@dataclass
class SemanticModel:
    pipeline: object

    def predict(self, texts: List[str]) -> List[int]:
        if hasattr(self.pipeline, 'predict'):
            return self.pipeline.predict(texts)  # type: ignore
        # fallback: expanded heuristic (command-exec, obfuscation, multilingual)
        keys = (
            "ignore", "bypass", "admin", "password", "system prompt",
            "execute", "run", "eval(", "system(", "subprocess", "curl ", "wget ", "rm -rf", "cat /etc/passwd",
            "base64", "hex",
            # French
            "ignorez", "négligez", "contournez", "montrez",
            # Chinese
            "忽略", "无视", "显示",
            # Spanish
            "ignora", "omite", "salta", "muestra",
            # Italian
            "istruzioni", "mostra"
        )
        return [1 if any(k in t.lower() for k in keys) else 0 for t in texts]

    def predict_proba(self, texts: List[str]) -> List[float]:
        if hasattr(self.pipeline, 'predict_proba'):
            proba = self.pipeline.predict_proba(texts)  # type: ignore
            return proba[:, 1]
        # fallback probabilities aligned with expanded heuristic
        keys = (
            "ignore", "bypass", "admin", "password", "system prompt",
            "execute", "run", "eval(", "system(", "subprocess", "curl ", "wget ", "rm -rf", "cat /etc/passwd",
            "base64", "hex",
            "ignorez", "négligez", "contournez", "montrez",
            "忽略", "无视", "显示",
            "ignora", "omite", "salta", "muestra",
            "istruzioni", "mostra"
        )
        out: List[float] = []
        for t in texts:
            tl = t.lower()
            prob = 0.1
            if any(k in tl for k in keys):
                prob = 0.95
            out.append(prob)
        return out


def train_semantic_model(pairs: List[Tuple[str, str]]) -> SemanticModel:
    texts = [p for p, _ in pairs]
    labels = [1 if y.lower() in ("adversarial", "attack", "malicious") else 0 for _, y in pairs]
    if TfidfVectorizer is None or LogisticRegression is None or Pipeline is None or np is None:
        # Fallback: hashed-char+word ngram logistic regression via SGD
        dim = int(os.getenv('SEM_HASH_DIM', '131072'))
        lr = float(os.getenv('SEM_LR', '0.1'))
        l2 = float(os.getenv('SEM_L2', '1e-6'))
        epochs = int(os.getenv('SEM_EPOCHS', '1'))
        train_limit = int(os.getenv('SEM_TRAIN_LIMIT', str(len(texts))))

        def word_ngrams(s: str) -> Iterable[str]:
            toks = [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]
            for t in toks:
                yield t
            for i in range(len(toks) - 1):
                yield toks[i] + '_' + toks[i+1]

        def char_ngrams(s: str, n_min: int = 3, n_max: int = 5) -> Iterable[str]:
            s = s.lower()
            for n in range(n_min, n_max + 1):
                for i in range(0, max(0, len(s) - n + 1)):
                    yield '#' + s[i:i+n]

        def featurize(text: str) -> List[Tuple[int, float]]:
            counts: Dict[int, int] = {}
            for token in word_ngrams(text):
                idx = hash(token) % dim
                counts[idx] = counts.get(idx, 0) + 1
            for token in char_ngrams(text):
                idx = hash(token) % dim
                counts[idx] = counts.get(idx, 0) + 1
            # L2-normalize
            norm = math.sqrt(sum(v*v for v in counts.values())) or 1.0
            return [(i, v / norm) for i, v in counts.items()]

        w = np.zeros(dim, dtype=np.float32)

        def predict_proba_one(feats: List[Tuple[int, float]]) -> float:
            z = 0.0
            for i, v in feats:
                z += float(w[i]) * v
            # sigmoid
            if z >= 0:
                ez = math.exp(-z)
                return 1.0 / (1.0 + ez)
            else:
                ez = math.exp(z)
                return ez / (1.0 + ez)

        # Train with SGD
        n_train = min(train_limit, len(texts))
        for _ in range(max(1, epochs)):
            for i in range(n_train):
                feats = featurize(texts[i])
                y = labels[i]
                p = predict_proba_one(feats)
                g = (y - p)
                # update
                for j, v in feats:
                    w[j] += lr * (g * v - l2 * float(w[j]))

        class HashingLogReg:
            def __init__(self, w_arr, featurize_fn):
                self.w = w_arr
                self.featurize_fn = featurize_fn
            def predict(self, arr: List[str]) -> List[int]:
                out: List[int] = []
                for a in arr:
                    feats = self.featurize_fn(a)
                    # proba
                    z = 0.0
                    for i, v in feats:
                        z += float(self.w[i]) * v
                    p = 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))
                    out.append(1 if p >= 0.5 else 0)
                return out
            def predict_proba(self, arr: List[str]):
                probs = []
                for a in arr:
                    feats = self.featurize_fn(a)
                    z = 0.0
                    for i, v in feats:
                        z += float(self.w[i]) * v
                    if z >= 0:
                        ez = math.exp(-z)
                        p1 = 1.0 / (1.0 + ez)
                    else:
                        ez = math.exp(z)
                        p1 = ez / (1.0 + ez)
                    probs.append([1.0 - p1, p1])
                return probs

        return SemanticModel(HashingLogReg(w, featurize))
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2), max_features=50000, min_df=2)),
        ("clf", LogisticRegression(max_iter=200))
    ])
    pipe.fit(texts, labels)
    return SemanticModel(pipe)


def evaluate_semantic_model(model: SemanticModel, pairs: List[Tuple[str, str]]) -> str:
    texts = [p for p, _ in pairs]
    labels = [1 if y.lower() in ("adversarial", "attack", "malicious") else 0 for _, y in pairs]
    if classification_report is None:
        preds = model.predict(texts)
        tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
        fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
        fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
        tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return f"precision={precision:.3f} recall={recall:.3f} f1={f1:.3f}"
    preds = model.pipeline.predict(texts)  # type: ignore
    return classification_report(labels, preds, target_names=["benign","adversarial"])
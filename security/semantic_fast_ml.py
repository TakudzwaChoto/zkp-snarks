#!/usr/bin/env python3

from typing import List, Tuple, Dict, Iterable
import math
import re
import random

# Simple tokenizer
_word_re = re.compile(r"[a-z0-9_]+", re.IGNORECASE)

def tokenize(text: str) -> List[str]:
    return _word_re.findall(text.lower())

# Feature extraction with hashing trick
class HashedVectorizer:
    def __init__(self, num_features: int = 1 << 18, use_char_ngrams: bool = True, use_word_ngrams: bool = True):
        self.num_features = num_features
        self.use_char_ngrams = use_char_ngrams
        self.use_word_ngrams = use_word_ngrams

    def _hash(self, s: str) -> int:
        return (hash(s) % self.num_features)

    def transform_one(self, text: str) -> Dict[int, float]:
        feats: Dict[int, float] = {}
        t = text.lower()
        if self.use_word_ngrams:
            tokens = tokenize(t)
            # unigrams + bigrams
            for tok in tokens:
                idx = self._hash("w1:" + tok)
                feats[idx] = feats.get(idx, 0.0) + 1.0
            for i in range(len(tokens) - 1):
                bg = tokens[i] + "_" + tokens[i + 1]
                idx = self._hash("w2:" + bg)
                feats[idx] = feats.get(idx, 0.0) + 1.0
        if self.use_char_ngrams:
            # char 3-5 grams
            s = re.sub(r"\s+", " ", t)
            for n in (3, 4, 5):
                for i in range(0, max(0, len(s) - n + 1)):
                    ng = s[i : i + n]
                    idx = self._hash(f"c{n}:" + ng)
                    feats[idx] = feats.get(idx, 0.0) + 1.0
        # L2 normalize counts
        norm = math.sqrt(sum(v * v for v in feats.values())) or 1.0
        for k in list(feats.keys()):
            feats[k] /= norm
        return feats

# Online logistic regression (sparse, hashed features)
class HashedLogReg:
    def __init__(self, num_features: int, l2: float = 1e-6, lr: float = 0.1):
        self.num_features = num_features
        self.l2 = l2
        self.lr = lr
        # Sparse weights
        self.weights: Dict[int, float] = {}
        self.bias: float = 0.0

    def _dot(self, x: Dict[int, float]) -> float:
        s = self.bias
        for k, v in x.items():
            s += self.weights.get(k, 0.0) * v
        return s

    def _sigmoid(self, z: float) -> float:
        if z > 35:
            return 1.0
        if z < -35:
            return 0.0
        return 1.0 / (1.0 + math.exp(-z))

    def predict_proba_one(self, x: Dict[int, float]) -> float:
        return self._sigmoid(self._dot(x))

    def update_one(self, x: Dict[int, float], y: int) -> None:
        # y in {0,1}
        p = self.predict_proba_one(x)
        err = p - y
        # update bias
        self.bias -= self.lr * err
        # update weights (sparse)
        for k, v in x.items():
            w = self.weights.get(k, 0.0)
            grad = err * v + self.l2 * w
            w_new = w - self.lr * grad
            if abs(w_new) < 1e-12:
                if k in self.weights:
                    del self.weights[k]
            else:
                self.weights[k] = w_new

    def predict_proba_batch(self, X: List[Dict[int, float]]) -> List[float]:
        return [self.predict_proba_one(x) for x in X]

# Public API
class SemanticFastML:
    def __init__(self, num_features: int = 1 << 18, l2: float = 1e-6, lr: float = 0.1):
        self.vec = HashedVectorizer(num_features=num_features)
        self.model = HashedLogReg(num_features=num_features, l2=l2, lr=lr)
        self.threshold: float = 0.5

    def fit(self, pairs: List[Tuple[str, str]], epochs: int = 2, seed: int = 7, max_samples: int = 100000) -> None:
        random.seed(seed)
        # Shuffle and subsample for speed
        data = list(pairs)
        random.shuffle(data)
        if len(data) > max_samples:
            data = data[:max_samples]
        # Train epochs
        for _ in range(epochs):
            random.shuffle(data)
            for text, label in data:
                x = self.vec.transform_one(text)
                y = 1 if label.lower() in ("adversarial", "attack", "malicious") else 0
                self.model.update_one(x, y)
        # Calibrate threshold on a small holdout to keep FPR low
        holdout = data[: min(5000, len(data))]
        scores: List[Tuple[float, int]] = []
        for text, label in holdout:
            x = self.vec.transform_one(text)
            s = self.model.predict_proba_one(x)
            y = 1 if label.lower() in ("adversarial", "attack", "malicious") else 0
            scores.append((s, y))
        # choose threshold that yields ~0.5% FPR while maximizing TPR
        best_thr = 0.5
        best_metric = -1.0
        for thr in [i / 100 for i in range(40, 90)]:
            tp = fp = tn = fn = 0
            for s, y in scores:
                pred = 1 if s >= thr else 0
                if y == 1 and pred == 1:
                    tp += 1
                elif y == 0 and pred == 1:
                    fp += 1
                elif y == 0 and pred == 0:
                    tn += 1
                else:
                    fn += 1
            fpr = fp / max(1, (fp + tn))
            tpr = tp / max(1, (tp + fn))
            metric = tpr - 2.0 * fpr
            if metric > best_metric:
                best_metric = metric
                best_thr = thr
        self.threshold = best_thr

    def predict_proba(self, texts: List[str]) -> List[float]:
        X = [self.vec.transform_one(t) for t in texts]
        return self.model.predict_proba_batch(X)

    def predict(self, texts: List[str]) -> List[int]:
        probs = self.predict_proba(texts)
        return [1 if p >= self.threshold else 0 for p in probs]
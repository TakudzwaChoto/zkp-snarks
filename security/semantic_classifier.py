#!/usr/bin/env python3

from typing import List, Tuple
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
    if TfidfVectorizer is None or LogisticRegression is None or Pipeline is None:
        # return heuristic model
        class Heuristic:
            def predict(self, texts: List[str]):
                keys = (
                    "ignore", "bypass", "admin", "password", "system prompt",
                    "execute", "run", "eval(", "system(", "subprocess", "curl ", "wget ", "rm -rf", "cat /etc/passwd",
                    "base64", "hex",
                    "ignorez", "négligez", "contournez", "montrez",
                    "忽略", "无视", "显示",
                    "ignora", "omite", "salta", "muestra",
                    "istruzioni", "mostra"
                )
                return [1 if any(k in t.lower() for k in keys) else 0 for t in texts]
            def predict_proba(self, texts: List[str]):
                keys = (
                    "ignore", "bypass", "admin", "password", "system prompt",
                    "execute", "run", "eval(", "system(", "subprocess", "curl ", "wget ", "rm -rf", "cat /etc/passwd",
                    "base64", "hex",
                    "ignorez", "négligez", "contournez", "montrez",
                    "忽略", "无视", "显示",
                    "ignora", "omite", "salta", "muestra",
                    "istruzioni", "mostra"
                )
                probs = []
                for t in texts:
                    tl = t.lower()
                    prob = 0.1
                    if any(k in tl for k in keys):
                        prob = 0.95
                    probs.append([1-prob, prob])
                return probs
        return SemanticModel(Heuristic())
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
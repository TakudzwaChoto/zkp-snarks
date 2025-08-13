#!/usr/bin/env python3

from typing import List, Tuple
from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

@dataclass
class SemanticModel:
    pipeline: Pipeline

    def predict(self, texts: List[str]) -> List[int]:
        return self.pipeline.predict(texts)

    def predict_proba(self, texts: List[str]) -> List[float]:
        proba = self.pipeline.predict_proba(texts)
        return proba[:, 1]


def train_semantic_model(pairs: List[Tuple[str, str]]) -> SemanticModel:
    texts = [p for p, _ in pairs]
    labels = [1 if y.lower() in ("adversarial", "attack", "malicious") else 0 for _, y in pairs]
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1,2), max_features=50000, min_df=2)),
        ("clf", LogisticRegression(max_iter=200))
    ])
    pipe.fit(texts, labels)
    return SemanticModel(pipe)


def evaluate_semantic_model(model: SemanticModel, pairs: List[Tuple[str, str]]) -> str:
    texts = [p for p, _ in pairs]
    labels = [1 if y.lower() in ("adversarial", "attack", "malicious") else 0 for _, y in pairs]
    preds = model.pipeline.predict(texts)
    return classification_report(labels, preds, target_names=["benign","adversarial"])
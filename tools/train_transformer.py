#!/usr/bin/env python3
import os
import json
from dataclasses import dataclass
from typing import List, Tuple

import pandas as pd
from datasets import Dataset
from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                          DataCollatorWithPadding, Trainer, TrainingArguments)


def load_pairs(path: str) -> List[Tuple[str, int]]:
    if path.endswith('.json'):
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        rows = []
        for row in data:
            prompt = str(row.get('prompt', ''))
            label = str(row.get('label', '')).lower()
            y = 1 if label in ('adversarial','attack','malicious') else 0
            if prompt:
                rows.append((prompt, y))
        return rows
    elif path.endswith('.csv'):
        df = pd.read_csv(path)
        pcol = [c for c in df.columns if c.lower() == 'prompt'][0]
        lcol = [c for c in df.columns if c.lower() == 'label'][0]
        lbl = df[lcol].astype(str).str.lower().map(lambda s: 1 if s in ('adversarial','attack','malicious') else 0)
        return list(zip(df[pcol].astype(str).tolist(), lbl.tolist()))
    else:
        raise ValueError('Unsupported dataset format. Use .json or .csv')


def main():
    model_name = os.getenv('MODEL_NAME', 'distilroberta-base')
    output_dir = os.getenv('OUTPUT_DIR', '/app/models/ft_distilroberta')
    train_path = os.getenv('TRAIN_DS')
    eval_path = os.getenv('EVAL_DS', train_path)
    assert train_path, 'TRAIN_DS env is required'

    train_pairs = load_pairs(train_path)
    eval_pairs = load_pairs(eval_path) if eval_path else train_pairs

    tokenizer = AutoTokenizer.from_pretrained(model_name)

    def to_ds(pairs: List[Tuple[str,int]]):
        df = pd.DataFrame({'text':[p for p,_ in pairs], 'label':[y for _,y in pairs]})
        return Dataset.from_pandas(df)

    train_ds = to_ds(train_pairs)
    eval_ds = to_ds(eval_pairs)

    def tokenize_fn(batch):
        return tokenizer(batch['text'], truncation=True, max_length=256)

    train_ds = train_ds.map(tokenize_fn, batched=True)
    eval_ds = eval_ds.map(tokenize_fn, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    collator = DataCollatorWithPadding(tokenizer)

    args = TrainingArguments(
        output_dir=output_dir,
        learning_rate=5e-5,
        per_device_train_batch_size=32,
        per_device_eval_batch_size=64,
        num_train_epochs=2,
        weight_decay=0.01,
        evaluation_strategy='epoch',
        save_strategy='epoch',
        load_best_model_at_end=True,
        metric_for_best_model='eval_loss',
        logging_steps=50,
        save_total_limit=2,
        report_to=[]
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        tokenizer=tokenizer,
        data_collator=collator,
    )

    trainer.train()
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"Saved fine-tuned model to {output_dir}")


if __name__ == '__main__':
    main()
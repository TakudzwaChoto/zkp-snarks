#!/usr/bin/env python3

import argparse
import os
import sys
import json
import pandas as pd

def main():
    ap = argparse.ArgumentParser(description='Fine-tune transformer on synthetic prompt dataset')
    ap.add_argument('--dataset', type=str, required=True, help='Path to JSON/CSV with columns prompt,label')
    ap.add_argument('--model', type=str, default='distilbert-base-uncased')
    ap.add_argument('--out', type=str, default='ml_models/distilbert_synth')
    ap.add_argument('--epochs', type=int, default=2)
    ap.add_argument('--batch', type=int, default=16)
    args = ap.parse_args()

    try:
        from datasets import Dataset
        from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                                  TrainingArguments, Trainer)
        import numpy as np
    except Exception as e:
        print(f"Transformers/datasets not available: {e}")
        print("Please install with: pip install transformers datasets torch --break-system-packages")
        sys.exit(1)

    # Load dataset
    if args.dataset.endswith('.json'):
        df = pd.read_json(args.dataset)
    elif args.dataset.endswith('.csv'):
        df = pd.read_csv(args.dataset)
    else:
        raise SystemExit('Dataset must be .json or .csv')
    if not set(['prompt','label']).issubset(df.columns):
        raise SystemExit('Dataset must contain columns: prompt,label')

    label_map = {'benign': 0, 'safe': 0, 'adversarial': 1, 'attack': 1, 'malicious': 1}
    df = df[['prompt','label']].copy()
    df['label_id'] = df['label'].map(lambda x: label_map.get(str(x).lower(), 0))

    # Small validation split
    val_frac = 0.05
    val_size = max(1000, int(len(df) * val_frac)) if len(df) > 20000 else max(200, int(len(df) * 0.1))
    df_val = df.sample(n=min(val_size, len(df)//5 or 1), random_state=42)
    df_train = df.drop(df_val.index)

    tokenizer = AutoTokenizer.from_pretrained(args.model)

    def tokenize_fn(batch):
        return tokenizer(batch['prompt'], truncation=True, padding='max_length', max_length=128)

    ds_train = Dataset.from_pandas(df_train[['prompt','label_id']]).rename_columns({'label_id':'labels'})
    ds_val = Dataset.from_pandas(df_val[['prompt','label_id']]).rename_columns({'label_id':'labels'})

    ds_train = ds_train.map(tokenize_fn, batched=True)
    ds_val = ds_val.map(tokenize_fn, batched=True)
    cols = ['input_ids','attention_mask','labels']
    ds_train = ds_train.remove_columns([c for c in ds_train.column_names if c not in cols])
    ds_val = ds_val.remove_columns([c for c in ds_val.column_names if c not in cols])

    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)

    os.makedirs(args.out, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=args.out,
        learning_rate=2e-5,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        num_train_epochs=args.epochs,
        weight_decay=0.01,
        evaluation_strategy='epoch',
        save_strategy='epoch',
        load_best_model_at_end=True,
        metric_for_best_model='eval_loss'
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = logits.argmax(axis=-1)
        acc = (preds == labels).mean()
        # Approx precision/recall
        tp = int(((preds == 1) & (labels == 1)).sum())
        fp = int(((preds == 1) & (labels == 0)).sum())
        tn = int(((preds == 0) & (labels == 0)).sum())
        fn = int(((preds == 0) & (labels == 1)).sum())
        prec = tp / (tp + fp) if (tp + fp) else 0
        rec = tp / (tp + fn) if (tp + fn) else 0
        f1 = (2*prec*rec/(prec+rec)) if (prec+rec) else 0
        return {'accuracy': float(acc), 'precision': float(prec), 'recall': float(rec), 'f1': float(f1)}

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=ds_train,
        eval_dataset=ds_val,
        compute_metrics=compute_metrics
    )

    trainer.train()
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"Saved model to {args.out}")

if __name__ == '__main__':
    main()
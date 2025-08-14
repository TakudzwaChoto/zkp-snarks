#!/usr/bin/env python3

import os
from typing import List
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
except Exception as e:
    AutoTokenizer = None
    AutoModelForSequenceClassification = None
    torch = None

MODEL_DIR = os.getenv('TRANSFORMER_MODEL_DIR', 'ml_models/distilbert_synth')
DEVICE = os.getenv('DEVICE', 'cpu')

app = FastAPI()

class InferRequest(BaseModel):
    texts: List[str]

class InferResponse(BaseModel):
    probs: List[float]

@app.on_event('startup')
async def load_model():
    global tokenizer, model, device
    if AutoTokenizer is None:
        print('Transformers not available; service will not run.')
        return
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    device = torch.device(DEVICE if torch.cuda.is_available() and DEVICE == 'cuda' else 'cpu')
    model.to(device)
    model.eval()

@app.post('/infer', response_model=InferResponse)
async def infer(req: InferRequest):
    if AutoTokenizer is None:
        return InferResponse(probs=[0.0 for _ in req.texts])
    with torch.no_grad():
        enc = tokenizer(req.texts, truncation=True, padding=True, max_length=128, return_tensors='pt')
        enc = {k: v.to(device) for k, v in enc.items()}
        logits = model(**enc).logits
        probs = torch.softmax(logits, dim=-1)[:, 1].detach().cpu().tolist()
    return InferResponse(probs=probs)

if __name__ == '__main__':
    port = int(os.getenv('PORT', '8100'))
    uvicorn.run(app, host='0.0.0.0', port=port)
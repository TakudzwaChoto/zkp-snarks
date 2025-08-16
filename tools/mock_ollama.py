#!/usr/bin/env python3
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
	try:
		data = request.get_json(force=True, silent=True) or {}
		messages = data.get('messages', [])
		content = ''
		for m in messages:
			if isinstance(m, dict) and m.get('role') == 'user':
				content = m.get('content', '')
				break
		reply = f"Safe reply: {content[:60]}" if content else "Safe reply."
		return jsonify({
			"id": "mockcmpl-123",
			"object": "chat.completion",
			"created": 0,
			"model": data.get('model', 'tinyllama:1.1b'),
			"choices": [
				{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}
			],
			"usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
		}), 200
	except Exception as e:
		return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
	port = int(os.getenv('PORT', '11434'))
	app.run(host='127.0.0.1', port=port)
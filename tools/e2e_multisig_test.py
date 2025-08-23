#!/usr/bin/env python3
import re
import sqlite3
from contextlib import contextmanager

from app import app, logger

@contextmanager
def test_client():
	# Disable CSRF for programmatic testing
	app.config['WTF_CSRF_ENABLED'] = False
	app.config['TESTING'] = True
	with app.test_client() as client:
		yield client

def reset_db():
	conn = sqlite3.connect('llm_logs.db')
	cur = conn.cursor()
	try:
		cur.execute('DELETE FROM log_signatures')
	except Exception:
		pass
	cur.execute('DELETE FROM logs')
	conn.commit()
	conn.close()

def login(client, username='admin', password='adminpass'):
	resp = client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)
	assert resp.status_code == 200, f"Login failed: {resp.status_code}"
	assert b'Logged in as' in resp.data or b'Welcome' in resp.data


def submit_prompt(client, prompt_text: str) -> int:
	# Ensure we can reach index
	resp = client.get('/')
	assert resp.status_code == 200
	# Post prompt
	resp = client.post('/', data={'prompt': prompt_text}, follow_redirects=True)
	assert resp.status_code == 200
	# Extract Log ID from flash
	m = re.search(rb'Log ID:\s*(\d+)', resp.data)
	if not m:
		# Fallback: query DB for last id if flash not present
		conn = sqlite3.connect('llm_logs.db')
		cur = conn.cursor()
		cur.execute('SELECT id FROM logs ORDER BY id DESC LIMIT 1')
		row = cur.fetchone()
		conn.close()
		assert row is not None, 'No log entry found after submission'
		return int(row[0])
	return int(m.group(1))


def verify_integrity(client):
	resp = client.get('/verify')
	assert resp.status_code == 200
	assert b'VALID' in resp.data


def main():
	reset_db()
	with test_client() as client:
		login(client)
		log_id = submit_prompt(client, 'What is the capital of France?')
		status = logger.get_log_status(log_id)
		assert status.get('status') == 'finalized', f"Unexpected status: {status}"
		verify_integrity(client)
	print('E2E test passed: log_id', log_id)

if __name__ == '__main__':
	main()
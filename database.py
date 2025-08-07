import sqlite3

def init_db():
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            prompt_encrypted TEXT NOT NULL,
            response_encrypted TEXT NOT NULL,
            previous_hash TEXT,
            current_hash TEXT NOT NULL,
            signature TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()
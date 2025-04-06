import sqlite3
import os
from datetime import datetime

def get_db_connection():
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect('data/urls.db')
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT CHECK(result IN ('safe', 'malicious')),
            threat_level TEXT CHECK(threat_level IN ('low', 'medium', 'high')),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_url(url, result, threat_level):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO url_checks (url, result, threat_level) VALUES (?, ?, ?)',
        (url, result, threat_level)
    )
    conn.commit()
    conn.close()

def get_history():
    conn = get_db_connection()
    history = conn.execute('''
        SELECT url, result, threat_level, 
               strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp
        FROM url_checks
        ORDER BY timestamp DESC
    ''').fetchall()
    conn.close()
    return [dict(row) for row in history]

# Initialize the database when this module is imported
init_db()
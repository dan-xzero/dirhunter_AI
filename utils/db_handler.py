# File: dirhunter_ai/utils/db_handler.py (extended)
import sqlite3, os, datetime

DB_FILE = "db/endpoint_hashes.sqlite"
os.makedirs("db", exist_ok=True)

# ─────────── setup ───────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_hashes (
            url TEXT PRIMARY KEY,
            sha1 TEXT,
            last_seen TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# ─────────── check + update ───────────
def get_stored_hash(url):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT sha1 FROM endpoint_hashes WHERE url = ?", (url,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def update_hash_record(url, sha1):
    now = datetime.datetime.utcnow()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO endpoint_hashes (url, sha1, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET sha1 = excluded.sha1, last_seen = excluded.last_seen
    """, (url, sha1, now))
    conn.commit()
    conn.close()

# ─────────── reset DB ───────────
def reset_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM endpoint_hashes")
    conn.commit()
    conn.close()
    print("[!] Database cleared: endpoint_hashes table is now empty.")

import sqlite3
from pathlib import Path
from datetime import datetime

DB = Path("application/data/threatshield.db")

conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_number TEXT UNIQUE,
    title TEXT,
    severity TEXT,
    status TEXT,
    description TEXT,
    source_alert_id INTEGER,
    created_at TEXT,
    updated_at TEXT
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    action TEXT,
    details TEXT,
    created_at TEXT
)
""")

conn.commit()

print("[+] Incident tables ready.")

conn.close()

#!/usr/bin/env python3
import sqlite3
DB_FILE = 'threat_intel.db'
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS iocs (
    ip_address TEXT PRIMARY KEY,
    abuse_confidence INTEGER,
    country_code TEXT,
    last_seen TEXT
)
''')
conn.commit()
conn.close()
print('Database initialized: threat_intel.db')

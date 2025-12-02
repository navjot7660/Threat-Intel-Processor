#!/usr/bin/env python3
"""Threat Intel Processor - Fetch blacklist from AbuseIPDB and check a log file for malicious IPs."""
import requests
import sqlite3
import os

API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'af12bc34d567ef890123examplekey')
DB_FILE = 'threat_intel.db'
BLACKLIST_URL = 'https://api.abuseipdb.com/api/v2/blacklist'

def setup_database():
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

def fetch_threat_feed(limit=500):
    if not API_KEY:
        print("No API key set. Set ABUSEIPDB_API_KEY environment variable.")
        return
    print("Fetching threat feed...")
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'limit': limit}
    try:
        response = requests.get(BLACKLIST_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for record in data.get('data', []):
        ip = record.get('ipAddress')
        score = record.get('abuseConfidenceScore', 0)
        country = record.get('countryCode')
        last_seen = record.get('lastReportedAt') if 'lastReportedAt' in record else None
        try:
            cursor.execute("INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?, ?, ?, ?)", (ip, score, country, last_seen))
        except sqlite3.Error:
            pass
    conn.commit()
    conn.close()
    print("Feed fetch complete. Database updated.")

def seed_demo_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    demo = [
        ('185.191.171.12', 100, 'US', '2025-10-28'),
        ('206.189.123.45', 92, 'IN', '2025-11-02'),
        ('45.77.123.89', 87, 'DE', '2025-09-15')
    ]
    for ip, score, cc, last in demo:
        cursor.execute("INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?, ?, ?, ?)", (ip, score, cc, last))
    conn.commit()
    conn.close()

def check_logs(log_file):
    print(f"Scanning log file: {log_file}")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        with open(log_file, 'r') as f:
            for line in f:
                ip = line.strip().split()[0]
                if not ip:
                    continue
                cursor.execute("SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs WHERE ip_address = ?", (ip,))
                result = cursor.fetchone()
                if result:
                    print(f" [!] ALERT: Malicious IP found: {result[0]} (Confidence: {result[1]}%, Country: {result[2]}, LastSeen: {result[3]})")
    except FileNotFoundError:
        print("Log file not found.")
    finally:
        conn.close()

if __name__ == '__main__':
    setup_database()
    seed_demo_data()
    fetch_threat_feed(limit=200)
    sample_log = 'access.log'
    if not os.path.exists(sample_log):
        with open(sample_log, 'w') as f:
            f.write('192.168.1.1\n')
            f.write('185.191.171.12\n')
            f.write('8.8.8.8\n')
            f.write('206.189.123.45\n')
    check_logs(sample_log)

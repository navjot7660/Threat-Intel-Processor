# Threat Intel Processor

Automated Python tool that fetches malicious IPs from AbuseIPDB, stores them in a local SQLite database,
and checks a log file for matches (IOCs).

Version: 1.0.3
Date: 2025-12-02

Repository contains implementation, documentation, and sample data for demonstration.

## Repo structure

```
threat-intel-processor/
├── README.md
├── LICENSE
├── requirements.txt
├── threat_checker.py
├── init_db.py
├── access.log
├── docs/
│   └── project_report.md
├── scripts/
│   └── run.sh
├── logs/
│   └── sample.log
└── .gitignore
```

## Quick start

1. Install dependencies (Ubuntu / Debian):
```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt
```

2. Set the AbuseIPDB API key as an environment variable:
```bash
export ABUSEIPDB_API_KEY=af12bc34d567ef890123examplekey
```

3. Initialize the database and run the script:
```bash
python3 init_db.py
python3 threat_checker.py
```

The script will create `threat_intel.db`, fetch the blacklist from AbuseIPDB and scan `access.log` for malicious IPs.

## Notes
Do NOT commit real API keys to a public repository. Use environment variables or secrets for production.
AbuseIPDB usage is subject to their terms and rate limits.

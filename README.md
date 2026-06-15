# 🛡️ AI SOC Analyst Assistant

An AI-powered security alert triage tool that analyzes logs, IOCs, and SIEM alerts in real time — returning structured threat reports with MITRE ATT&CK mappings, severity ratings, and recommended response actions.

Built as a portfolio project demonstrating SOC Tier 1/2 analyst skills combined with practical AI integration.

---

## 🎯 Project Overview

SOC analysts spend a significant portion of their shift triaging alerts — determining severity, identifying threat type, and deciding on next steps. This tool automates the initial triage layer, allowing analysts to focus on investigation and response.

The assistant accepts raw alert data from any source (SIEM, EDR, IDS, firewall, email gateway) and returns a structured triage report in seconds.

---

## ✨ Features

- **Alert Triage** — Paste raw SIEM/EDR/IDS alerts and receive instant structured analysis
- **IOC Analysis** — Analyze IP addresses, domains, file hashes, and URLs for threat context
- **Log Analyzer** — Submit raw log lines (auth.log, Windows Event Log, Sysmon, firewall) for anomaly detection
- **MITRE ATT&CK Mapping** — Every alert maps to relevant tactics and techniques (e.g. `Credential Access: Brute Force (T1110)`)
- **Severity Scoring** — Automated CRITICAL / HIGH / MEDIUM / LOW / INFO classification
- **IOC Extraction** — Pulls structured indicators from unstructured alert data
- **Recommended Actions** — Prioritized response steps for each alert
- **False Positive Assessment** — Reduces alert fatigue with likelihood scoring

---

## 🖥️ Demo

| Alert Triage | IOC Lookup | Log Analyzer |
|---|---|---|
| Paste any SIEM alert | Analyze IPs, hashes, domains | Submit raw log lines |

**Pre-loaded examples included:**
- SSH Brute Force (Wazuh rule trigger)
- Phishing Email (Proofpoint gateway alert)
- Lateral Movement (Windows Event ID 4624)
- Data Exfiltration (DLP + Firewall combined alert)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│              Browser / Frontend              │
│   (HTML + Vanilla JS, three analysis modes) │
└─────────────────────┬───────────────────────┘
                      │ HTTPS
                      ▼
┌─────────────────────────────────────────────┐
│           Anthropic Claude API               │
│        claude-sonnet-4-6 model               │
│   System prompt: SOC analyst persona +       │
│   structured JSON schema enforcement         │
└─────────────────────────────────────────────┘
```

**Backend variant (see `backend/`):**

```
SIEM / Log Source  →  Python Ingest  →  Claude API  →  Structured Report  →  Dashboard
```

---

## 🚀 Quick Start

### Option 1 — Browser (no setup)

Open `index.html` directly in your browser. The tool calls the Anthropic API client-side.

> ⚠️ For production use, move API calls to a backend server to protect your API key.

### Option 2 — Python Backend

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/ai-soc-analyst.git
cd ai-soc-analyst

# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY=your_key_here

# Run the backend
python backend/app.py
```

Then open `http://localhost:5000` in your browser.

---

## 📁 Project Structure

```
ai-soc-analyst/
├── index.html              # Frontend — standalone single-file app
├── backend/
│   ├── app.py              # Flask API server
│   ├── analyzer.py         # Core triage logic
│   ├── prompts.py          # System prompt templates
│   └── schemas.py          # Pydantic response models
├── samples/
│   ├── brute_force.log     # Sample SSH brute force logs
│   ├── phishing.eml        # Sample phishing email headers
│   ├── lateral_movement.evtx.txt   # Sample Windows Event logs
│   └── exfiltration.log    # Sample DLP alert logs
├── docs/
│   ├── TECHNICAL.md        # Architecture and design details
│   └── screenshots/        # UI screenshots
├── requirements.txt
└── README.md
```

---

## 🔬 Sample Output

**Input:** SSH brute force alert (45 failed login attempts in 3 seconds)

**Output:**
```json
{
  "severity": "HIGH",
  "summary": "Automated brute force attack detected against SSH service from external IP 45.33.32.156. 45 failed authentication attempts in under 3 seconds targeting common usernames (admin, root, ubuntu). No successful logins observed.",
  "threat_type": "Credential Access: Brute Force",
  "mitre": [
    "Credential Access: Brute Force (T1110)",
    "Initial Access: External Remote Services (T1133)"
  ],
  "iocs": [
    { "type": "IP", "value": "45.33.32.156" },
    { "type": "Process", "value": "sshd" }
  ],
  "actions": [
    "Block source IP 45.33.32.156 at the perimeter firewall immediately",
    "Verify no successful logins occurred from this IP in the last 24 hours",
    "Enable fail2ban or equivalent rate-limiting on SSH service",
    "Audit SSH configuration — disable root login and enforce key-based auth",
    "Search for this IP across other assets in the environment"
  ],
  "false_positive_likelihood": "Very low. 45 failed attempts in 3 seconds from a single external IP is consistent with automated tooling (Hydra, Medusa). Legitimate users do not fail login at this rate."
}
```

---

## 🧠 Skills Demonstrated

This project showcases skills directly relevant to SOC Tier 1 / Tier 2 roles:

| Skill | How it's demonstrated |
|---|---|
| Log analysis | Parsing auth.log, Windows Event Log, firewall logs |
| SIEM alert triage | Structured severity classification from raw alerts |
| MITRE ATT&CK framework | Automatic technique mapping per alert |
| IOC identification | Extracting indicators from unstructured data |
| Incident response | Prioritized remediation recommendations |
| Python scripting | Backend Flask API, log ingestion pipeline |
| API integration | Anthropic Claude API, VirusTotal (roadmap) |
| AI/ML tooling | Prompt engineering for structured security outputs |

---

## 🗺️ Roadmap

- [ ] VirusTotal API integration for live IOC reputation lookup
- [ ] AbuseIPDB integration for IP reputation scoring
- [ ] MITRE ATT&CK Navigator layer export
- [ ] Alert history and case management (SQLite)
- [ ] Slack / webhook alerting for high-severity findings
- [ ] Home lab integration (Wazuh SIEM → real-time alert feed)
- [ ] PCAP upload support for network traffic analysis

---

## 🔧 Requirements

```
anthropic>=0.25.0
flask>=3.0.0
python-dotenv>=1.0.0
pydantic>=2.0.0
requests>=2.31.0
```

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Gyelzen (Zen) L. Sherpa**
- B.S. Cybersecurity & Information Assurance — Western Governors University (2026)
- CompTIA CySA+ | PenTest+ | Security+ | Network+ | ISC2 SSCP
- [LinkedIn](https://linkedin.com/in/YOUR_HANDLE) · [GitHub](https://github.com/YOUR_USERNAME)

> Built as part of an ongoing portfolio demonstrating hands-on cybersecurity skills. Feedback and contributions welcome.

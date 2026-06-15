# Technical Documentation

## AI SOC Analyst Assistant — Architecture & Design

---

## Table of Contents

1. [System Design](#system-design)
2. [Prompt Engineering](#prompt-engineering)
3. [Response Schema](#response-schema)
4. [Analysis Modes](#analysis-modes)
5. [MITRE ATT&CK Mapping Logic](#mitre-attck-mapping-logic)
6. [Backend API](#backend-api)
7. [Security Considerations](#security-considerations)
8. [Home Lab Integration](#home-lab-integration)
9. [Extending the Tool](#extending-the-tool)

---

## System Design

### Core Concept

The tool uses a single AI model call per analysis request. Rather than a multi-step pipeline, all triage logic — severity scoring, IOC extraction, MITRE mapping, action generation — is handled in one structured prompt. This keeps latency low (typically 2–4 seconds) and cost minimal.

```
User Input (alert / IOC / log)
        │
        ▼
┌───────────────────┐
│   Input Layer     │  Sanitize, validate, format into prompt
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Prompt Engine   │  System prompt + user content → Claude API request
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Claude API      │  claude-sonnet-4-6, max_tokens=1000, JSON-only output
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Output Parser   │  JSON.parse(), schema validation, error handling
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   UI Renderer     │  Severity badge, MITRE pills, action list, IOC grid
└───────────────────┘
```

### Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Frontend | Vanilla HTML/JS | Zero dependencies, runs anywhere, easy to audit |
| AI Model | Anthropic claude-sonnet-4-6 | Best balance of speed, cost, and security reasoning |
| Backend (optional) | Python + Flask | Simple REST API, easy to extend |
| Data validation | Pydantic (backend) | Strict schema enforcement on AI outputs |
| API key protection | Server-side only (backend) | Never expose API keys in client-side code |

---

## Prompt Engineering

The most critical design decision in this tool is the system prompt. It does four things:

1. Establishes the AI persona (expert SOC analyst)
2. Enforces structured JSON output — no prose, no markdown
3. Defines the exact output schema
4. Sets behavioral guardrails (consistent severity definitions)

### System Prompt

```
You are an expert SOC analyst AI assistant. Analyze security alerts, logs,
and IOCs. Always respond ONLY with valid JSON, no markdown, no preamble.
Use this exact schema:

{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "2-3 sentence plain-language summary",
  "threat_type": "classification e.g. Brute Force, Phishing, Lateral Movement...",
  "mitre": ["Tactic: Technique (TXXXX)", ...],
  "iocs": [{"type": "IP|Domain|Hash|URL|Email|Process", "value": "..."}, ...],
  "actions": ["Recommended action 1", ...],
  "false_positive_likelihood": "Assessment with brief reasoning"
}
```

### Why JSON-only output?

Structured output is essential for programmatic parsing. Instructing the model to return only JSON (with no markdown fences or preamble) eliminates the need for regex-based text extraction, which is fragile and error-prone.

The response is parsed with:

```javascript
const text = data.content.map(c => c.text || '').join('');
const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
```

The `.replace()` is a safety net — in practice the model respects the JSON-only instruction, but this handles edge cases gracefully.

### Severity Definitions

The model infers severity from the alert content, guided by standard SOC practice:

| Severity | Definition |
|---|---|
| CRITICAL | Active compromise, ransomware, confirmed data exfiltration, domain controller attack |
| HIGH | Brute force with successful login, C2 communication, privilege escalation |
| MEDIUM | Brute force (no success), phishing email delivered, suspicious process |
| LOW | Reconnaissance, port scan, single failed login, informational anomaly |
| INFO | Policy violation, benign misconfiguration, known false positive pattern |

---

## Response Schema

Full schema with field definitions:

```typescript
interface TriageReport {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

  // 2-3 sentences: what happened, where, any context
  summary: string;

  // Human-readable threat classification
  // Examples: "Credential Access: Brute Force", "Phishing", "Lateral Movement via SMB"
  threat_type: string;

  // MITRE ATT&CK techniques, format: "Tactic: Technique (TXXXX)"
  mitre: string[];

  // Extracted indicators of compromise
  iocs: Array<{
    type: "IP" | "Domain" | "Hash" | "URL" | "Email" | "Process" | "Registry" | "File";
    value: string;
  }>;

  // Prioritized response actions, most urgent first
  actions: string[];

  // False positive likelihood with reasoning
  false_positive_likelihood: string;
}
```

### Pydantic Model (backend)

```python
from pydantic import BaseModel
from typing import Literal

class IOC(BaseModel):
    type: Literal["IP", "Domain", "Hash", "URL", "Email", "Process", "Registry", "File"]
    value: str

class TriageReport(BaseModel):
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    summary: str
    threat_type: str
    mitre: list[str]
    iocs: list[IOC]
    actions: list[str]
    false_positive_likelihood: str
```

---

## Analysis Modes

### 1. Alert Triage

Accepts: alert type/source, raw alert text, optional source IP, optional destination host.

The prompt is assembled as:

```
Analyze this security alert:
Alert type/source: {alert_type}
Source IP: {src_ip}
Destination: {destination}
Raw data:
{raw_alert}
```

Best used with: SIEM rule triggers, EDR alerts, IDS/IPS events, firewall blocks.

### 2. IOC Analysis

Accepts: a single IOC value (IP, domain, hash, URL), optional context.

```
Analyze this IOC: {ioc_value}
Context: {context}
Provide a threat assessment including what this IOC likely represents,
associated threat actors or malware families if known, severity,
and recommended defensive actions.
```

Best used with: threat hunting, email link analysis, malware hash lookup, suspicious domain investigation.

### 3. Log Analyzer

Accepts: log source name, raw log lines (any format).

```
Analyze these logs from {log_source} for security anomalies,
suspicious patterns, or indicators of compromise:

{log_data}
```

Best used with: auth.log, /var/log/syslog, Windows Event Logs, Sysmon output, firewall logs, web server access logs.

---

## MITRE ATT&CK Mapping Logic

The model maps alerts to MITRE ATT&CK techniques based on behavioral patterns in the alert data. No lookup table is used — the model applies its training knowledge of the ATT&CK framework.

### Format

All techniques are returned in the format:

```
"Tactic: Technique (TXXXX)"
```

Example outputs:

| Alert Type | Expected MITRE Techniques |
|---|---|
| SSH brute force | `Credential Access: Brute Force (T1110)`, `Initial Access: External Remote Services (T1133)` |
| Phishing email | `Initial Access: Phishing (T1566)`, `Execution: User Execution (T1204)` |
| Lateral movement via SMB | `Lateral Movement: SMB/Windows Admin Shares (T1021.002)`, `Discovery: Network Share Discovery (T1135)` |
| PowerShell data exfil | `Exfiltration: Exfiltration Over C2 Channel (T1041)`, `Execution: PowerShell (T1059.001)` |
| Suspicious scheduled task | `Persistence: Scheduled Task (T1053.005)`, `Privilege Escalation: Scheduled Task (T1053.005)` |

### Roadmap: MITRE ATT&CK Navigator Export

A planned feature will export the MITRE techniques from any triage session as an ATT&CK Navigator JSON layer file, which can be imported at `https://mitre-attack.github.io/attack-navigator/` to visualize coverage.

---

## Backend API

The optional Python backend exposes a REST API, useful for integration with real SIEM webhooks.

### Endpoints

```
POST /api/triage
POST /api/ioc
POST /api/logs
GET  /api/health
```

### POST /api/triage

```json
// Request
{
  "alert_type": "Wazuh Rule 5763",
  "raw_alert": "Jan 15 03:42:11 sshd[2891]: Failed password...",
  "src_ip": "45.33.32.156",
  "destination": "webserver.prod"
}

// Response
{
  "severity": "HIGH",
  "summary": "...",
  "threat_type": "Credential Access: Brute Force",
  "mitre": ["..."],
  "iocs": [{"type": "IP", "value": "45.33.32.156"}],
  "actions": ["..."],
  "false_positive_likelihood": "..."
}
```

### app.py (core)

```python
from flask import Flask, request, jsonify
from analyzer import analyze_alert, analyze_ioc, analyze_logs
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

@app.route('/api/triage', methods=['POST'])
def triage():
    data = request.get_json()
    result = analyze_alert(
        alert_type=data.get('alert_type', 'Unknown'),
        raw_alert=data['raw_alert'],
        src_ip=data.get('src_ip', 'N/A'),
        destination=data.get('destination', 'N/A')
    )
    return jsonify(result)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=False, port=5000)
```

### analyzer.py

```python
import os
import json
import anthropic

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are an expert SOC analyst AI assistant. Analyze security
alerts, logs, and IOCs. Always respond ONLY with valid JSON matching this schema:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "2-3 sentence plain-language summary",
  "threat_type": "threat classification",
  "mitre": ["Tactic: Technique (TXXXX)"],
  "iocs": [{"type": "IP|Domain|Hash|URL|Email|Process", "value": "..."}],
  "actions": ["action 1", "action 2"],
  "false_positive_likelihood": "assessment with reasoning"
}"""

def analyze_alert(alert_type, raw_alert, src_ip, destination):
    prompt = f"""Analyze this security alert:
Alert type/source: {alert_type}
Source IP: {src_ip}
Destination: {destination}
Raw data:
{raw_alert}"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}]
    )

    text = response.content[0].text
    return json.loads(text.strip())

def analyze_ioc(ioc_value, context="None provided"):
    prompt = f"""Analyze this IOC: {ioc_value}
Context: {context}
Provide threat assessment, associated threat actors or malware families if known,
severity, and recommended defensive actions."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}]
    )
    return json.loads(response.content[0].text.strip())

def analyze_logs(log_source, log_data):
    prompt = f"""Analyze these logs from {log_source} for security anomalies,
suspicious patterns, or indicators of compromise:

{log_data}"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}]
    )
    return json.loads(response.content[0].text.strip())
```

---

## Security Considerations

### API Key Handling

- Never embed the API key in client-side JavaScript for production use
- Use environment variables: `export ANTHROPIC_API_KEY=sk-ant-...`
- In `.env` files, always add `.env` to `.gitignore`
- For public deployment, route all API calls through your backend

### Input Sanitization

The tool passes user input directly into prompts. For production:

```python
def sanitize_input(text: str, max_length: int = 4000) -> str:
    # Truncate oversized inputs
    text = text[:max_length]
    # Remove null bytes
    text = text.replace('\x00', '')
    return text.strip()
```

### Prompt Injection Awareness

Malicious alert data could attempt to override the system prompt. Mitigations:

- Keep user content strictly in the `user` role, never the `system` role
- Validate that responses match the expected JSON schema before displaying
- Rate-limit the API endpoint to prevent abuse

### .gitignore

```
.env
*.env
__pycache__/
*.pyc
.DS_Store
venv/
node_modules/
```

---

## Home Lab Integration

This tool is designed to integrate with a real home lab environment — specifically a Wazuh SIEM feeding alerts into the triage pipeline.

### Wazuh → AI Triage Pipeline

```
Raspberry Pi (SecurePi / Wazuh Agent)
        │
        │ syslog / ossec alerts
        ▼
Wazuh Manager (alert JSON)
        │
        │ webhook / REST
        ▼
Python Ingest Script (backend/ingest.py)
        │
        │ POST /api/triage
        ▼
AI Triage Engine
        │
        ▼
Structured Report (severity, MITRE, actions)
        │
        ▼
Dashboard / Slack notification
```

### Sample Wazuh Webhook Integration

```python
# backend/ingest.py
# Listens for Wazuh webhook alerts and routes to AI triage

from flask import Flask, request
import requests

app = Flask(__name__)
TRIAGE_URL = "http://localhost:5000/api/triage"

@app.route('/wazuh-webhook', methods=['POST'])
def wazuh_alert():
    alert = request.get_json()

    # Map Wazuh fields to triage format
    payload = {
        "alert_type": f"Wazuh Rule {alert.get('rule', {}).get('id', 'Unknown')}",
        "raw_alert": alert.get('full_log', ''),
        "src_ip": alert.get('data', {}).get('srcip', 'N/A'),
        "destination": alert.get('agent', {}).get('name', 'N/A')
    }

    # Only triage alerts at level 7+ (medium+ severity)
    if alert.get('rule', {}).get('level', 0) >= 7:
        result = requests.post(TRIAGE_URL, json=payload).json()
        print(f"[{result['severity']}] {result['summary']}")

    return '', 200
```

---

## Extending the Tool

### Adding VirusTotal IOC Enrichment

```python
import requests

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def enrich_ip(ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(url, headers=headers).json()
    stats = resp.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }
```

### Adding AbuseIPDB Reputation

```python
def check_abuseipdb(ip: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": os.environ.get("ABUSEIPDB_KEY"), "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(url, headers=headers, params=params).json()
    data = resp.get("data", {})
    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country_code": data.get("countryCode", "Unknown")
    }
```

### Injecting Enrichment into the Triage Prompt

```python
def analyze_alert_enriched(alert_type, raw_alert, src_ip, destination):
    # Enrich the IP before analysis
    vt_data = enrich_ip(src_ip) if src_ip != 'N/A' else {}
    abuse_data = check_abuseipdb(src_ip) if src_ip != 'N/A' else {}

    enrichment = ""
    if vt_data:
        enrichment = f"\nThreat Intel: VirusTotal detections: {vt_data['malicious']}/90 engines malicious. AbuseIPDB score: {abuse_data.get('abuse_confidence_score', 'N/A')}%"

    prompt = f"""Analyze this security alert:
Alert type/source: {alert_type}
Source IP: {src_ip}
Destination: {destination}
{enrichment}
Raw data:
{raw_alert}"""

    # ... rest of API call
```

---

## Performance Notes

| Metric | Typical Value |
|---|---|
| API response time | 2–4 seconds |
| Token usage per request | ~400–700 tokens |
| Cost per analysis (claude-sonnet-4-6) | ~$0.002–0.004 USD |
| Concurrent requests supported | Unlimited (API rate limits apply) |

For high-volume environments (>100 alerts/hour), consider:
- Batching low-severity alerts for bulk analysis
- Caching repeated IOC lookups (Redis / SQLite)
- Pre-filtering with rule-based logic before AI triage

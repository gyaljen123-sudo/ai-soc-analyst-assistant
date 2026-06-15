#!/usr/bin/env python3
"""
AI SOC Analyst Assistant — Backend Server
==========================================
Flask REST API that wraps the Anthropic Claude API for security alert triage.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python app.py

Endpoints:
    POST /api/triage   - Triage a SIEM/EDR/IDS alert
    POST /api/ioc      - Analyze an indicator of compromise
    POST /api/logs     - Analyze raw log data
    GET  /api/health   - Health check
"""

import os
import json
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import anthropic
from pydantic import BaseModel, ValidationError
from typing import Literal

# ── Setup ──────────────────────────────────────────────────────────────────────

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
MODEL = "claude-sonnet-4-6"
MAX_INPUT_LENGTH = 4000


# ── Pydantic Schemas ───────────────────────────────────────────────────────────

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


# ── System Prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst AI assistant.
Your job is to analyze security alerts, raw logs, and indicators of compromise (IOCs).

Severity definitions:
- CRITICAL: Active confirmed compromise, ransomware, domain controller attack, confirmed exfiltration
- HIGH: Brute force with successful login, C2 communication, privilege escalation, phishing click
- MEDIUM: Brute force (no success), phishing email delivered, suspicious process, anomalous traffic
- LOW: Reconnaissance, port scan, single failed login, policy violation
- INFO: Known benign activity, testing artifacts, informational anomaly

MITRE ATT&CK format: "Tactic: Technique (TXXXX)" or "Tactic: Technique: Sub-technique (TXXXX.XXX)"

Always respond ONLY with valid JSON. No markdown fences, no preamble, no explanation outside the JSON.

Required schema:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "2-3 sentence plain-language summary of what happened and why it matters",
  "threat_type": "Human-readable threat classification",
  "mitre": ["Tactic: Technique (TXXXX)", ...],
  "iocs": [{"type": "IP|Domain|Hash|URL|Email|Process|Registry|File", "value": "..."}, ...],
  "actions": ["Most urgent action first", "Second action", ...],
  "false_positive_likelihood": "Low/Medium/High with 1-2 sentence reasoning"
}"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def sanitize(text: str) -> str:
    """Basic input sanitization."""
    if not text:
        return ""
    text = text[:MAX_INPUT_LENGTH]
    text = text.replace('\x00', '')
    return text.strip()

def call_claude(user_prompt: str) -> dict:
    """Call Claude API and return validated JSON dict."""
    response = client.messages.create(
        model=MODEL,
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}]
    )
    raw = response.content[0].text.strip()
    # Safety net: strip markdown fences if model includes them
    raw = raw.replace("```json", "").replace("```", "").strip()
    return json.loads(raw)

def validate_report(data: dict) -> dict:
    """Validate response against Pydantic schema. Returns dict."""
    try:
        report = TriageReport(**data)
        return report.model_dump()
    except ValidationError as e:
        log.warning(f"Schema validation warning: {e}")
        # Return raw data even if validation fails — don't block the response
        return data


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "model": MODEL})


@app.route('/api/triage', methods=['POST'])
def triage():
    """
    Triage a SIEM, EDR, IDS, or firewall alert.

    Request body:
        alert_type  (str, optional) - e.g. "Wazuh Rule 5763", "CrowdStrike EDR"
        raw_alert   (str, required) - raw alert text, log line, or event data
        src_ip      (str, optional) - source IP address
        destination (str, optional) - destination host or IP
    """
    data = request.get_json(silent=True)
    if not data or not data.get('raw_alert'):
        return jsonify({"error": "raw_alert is required"}), 400

    prompt = f"""Analyze this security alert:
Alert type/source: {sanitize(data.get('alert_type', 'Unknown'))}
Source IP: {sanitize(data.get('src_ip', 'N/A'))}
Destination: {sanitize(data.get('destination', 'N/A'))}
Raw data:
{sanitize(data['raw_alert'])}"""

    try:
        result = call_claude(prompt)
        validated = validate_report(result)
        log.info(f"Triage complete — severity: {validated.get('severity')} | threat: {validated.get('threat_type')}")
        return jsonify(validated)
    except json.JSONDecodeError as e:
        log.error(f"JSON parse error: {e}")
        return jsonify({"error": "AI returned malformed JSON", "detail": str(e)}), 500
    except anthropic.APIError as e:
        log.error(f"Anthropic API error: {e}")
        return jsonify({"error": "API call failed", "detail": str(e)}), 502
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/api/ioc', methods=['POST'])
def ioc():
    """
    Analyze an indicator of compromise.

    Request body:
        ioc_value (str, required) - IP, domain, hash, URL, email, etc.
        context   (str, optional) - Where/how this IOC was observed
    """
    data = request.get_json(silent=True)
    if not data or not data.get('ioc_value'):
        return jsonify({"error": "ioc_value is required"}), 400

    prompt = f"""Analyze this indicator of compromise (IOC):
IOC: {sanitize(data['ioc_value'])}
Context: {sanitize(data.get('context', 'None provided'))}

Provide:
- What this IOC likely represents
- Associated threat actors or malware families if known
- Severity assessment
- Recommended defensive actions
- False positive likelihood"""

    try:
        result = call_claude(prompt)
        validated = validate_report(result)
        log.info(f"IOC analysis complete — {data['ioc_value'][:50]} | severity: {validated.get('severity')}")
        return jsonify(validated)
    except json.JSONDecodeError as e:
        return jsonify({"error": "AI returned malformed JSON", "detail": str(e)}), 500
    except anthropic.APIError as e:
        return jsonify({"error": "API call failed", "detail": str(e)}), 502
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/api/logs', methods=['POST'])
def logs():
    """
    Analyze raw log data for security anomalies.

    Request body:
        log_source (str, optional) - e.g. "auth.log", "Windows Event Log", "Sysmon"
        log_data   (str, required) - raw log lines to analyze
    """
    data = request.get_json(silent=True)
    if not data or not data.get('log_data'):
        return jsonify({"error": "log_data is required"}), 400

    prompt = f"""Analyze these logs from {sanitize(data.get('log_source', 'unknown source'))} for:
- Security anomalies and suspicious patterns
- Indicators of compromise
- Unusual authentication events
- Signs of persistence, lateral movement, or exfiltration
- Policy violations

Log data:
{sanitize(data['log_data'])}"""

    try:
        result = call_claude(prompt)
        validated = validate_report(result)
        log.info(f"Log analysis complete — severity: {validated.get('severity')}")
        return jsonify(validated)
    except json.JSONDecodeError as e:
        return jsonify({"error": "AI returned malformed JSON", "detail": str(e)}), 500
    except anthropic.APIError as e:
        return jsonify({"error": "API call failed", "detail": str(e)}), 502
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ── Wazuh Webhook Integration (optional) ───────────────────────────────────────

@app.route('/api/wazuh-webhook', methods=['POST'])
def wazuh_webhook():
    """
    Receives Wazuh alert webhooks and routes level 7+ alerts to AI triage.

    Configure in Wazuh ossec.conf:
        <integration>
            <name>custom-webhook</name>
            <hook_url>http://YOUR_SERVER:5000/api/wazuh-webhook</hook_url>
            <level>7</level>
            <alert_format>json</alert_format>
        </integration>
    """
    alert = request.get_json(silent=True)
    if not alert:
        return '', 400

    rule_level = alert.get('rule', {}).get('level', 0)
    rule_id = alert.get('rule', {}).get('id', 'Unknown')

    # Only triage medium+ severity alerts
    if rule_level < 7:
        return jsonify({"status": "skipped", "reason": f"Level {rule_level} below threshold"}), 200

    payload = {
        "alert_type": f"Wazuh Rule {rule_id} (Level {rule_level})",
        "raw_alert": alert.get('full_log', json.dumps(alert.get('data', {}))),
        "src_ip": alert.get('data', {}).get('srcip', alert.get('decoder', {}).get('srcip', 'N/A')),
        "destination": alert.get('agent', {}).get('name', 'N/A')
    }

    try:
        prompt = f"""Analyze this Wazuh security alert:
Alert type/source: {payload['alert_type']}
Agent/Host: {payload['destination']}
Source IP: {payload['src_ip']}
Rule description: {alert.get('rule', {}).get('description', 'N/A')}
Raw data:
{sanitize(payload['raw_alert'])}"""

        result = call_claude(prompt)
        validated = validate_report(result)

        log.info(f"[WAZUH] Rule {rule_id} Level {rule_level} → AI severity: {validated.get('severity')} | {validated.get('threat_type')}")

        # TODO: Send high/critical alerts to Slack, PagerDuty, etc.
        if validated.get('severity') in ('CRITICAL', 'HIGH'):
            log.warning(f"[HIGH PRIORITY] {validated.get('summary')}")

        return jsonify({"status": "analyzed", "result": validated})
    except Exception as e:
        log.error(f"Wazuh webhook error: {e}")
        return jsonify({"error": str(e)}), 500


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not os.environ.get("ANTHROPIC_API_KEY"):
        log.error("ANTHROPIC_API_KEY environment variable not set. Exiting.")
        exit(1)

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    log.info(f"Starting AI SOC Analyst backend on port {port}")
    log.info(f"Model: {MODEL}")
    app.run(host='0.0.0.0', port=port, debug=debug)

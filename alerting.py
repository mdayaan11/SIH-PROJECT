"""
Multi-channel alert dispatch system for ENCLIVRA.

Channels:
  1. WebSocket push — real-time JSON to all connected browser clients
  2. Webhook POST  — configurable URL (Slack, Teams, Splunk HEC, etc.)
  3. Email (SMTP)  — CRITICAL severity only (disabled by default, set env vars)

Deduplication:
  One alert per (threat_type + source_ip) per 60 seconds.

Config via environment variables:
  ALERT_WEBHOOK_URL   — Webhook endpoint (optional)
  ALERT_EMAIL_FROM    — Sender address
  ALERT_EMAIL_TO      — Recipient address
  ALERT_SMTP_HOST     — SMTP host (default: smtp.gmail.com)
  ALERT_SMTP_PORT     — SMTP port (default: 587)
  ALERT_SMTP_USER     — SMTP username
  ALERT_SMTP_PASS     — SMTP password / app password
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger("enclave.alerting")

# ---------------------------------------------------------------------------
# Dedup state
# ---------------------------------------------------------------------------
_dedup_cache: dict[str, float] = {}  # key → last_sent_ts
_DEDUP_WINDOW = 60.0  # seconds


def _dedup_key(alert: dict[str, Any]) -> str:
    threat = alert.get("threat_type", "unknown")
    ips = ",".join(sorted(alert.get("source_ips", [])))
    return f"{threat}:{ips}"


def _is_duplicate(alert: dict[str, Any]) -> bool:
    key = _dedup_key(alert)
    last = _dedup_cache.get(key, 0.0)
    if time.time() - last < _DEDUP_WINDOW:
        return True
    _dedup_cache[key] = time.time()
    return False


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
async def _send_webhook(alert: dict[str, Any]) -> None:
    url = os.getenv("ALERT_WEBHOOK_URL", "")
    if not url or not HTTPX_AVAILABLE:
        return

    # Build a clean payload (Slack-compatible + raw JSON)
    severity = alert.get("severity", "medium").upper()
    title = alert.get("title", "Threat Alert")
    description = alert.get("description", "")
    source_ips = alert.get("source_ips", [])
    mitre = alert.get("mitre", {})
    mitre_tactic = mitre.get("tactic", "Unknown")

    payload = {
        "text": f"🚨 *[{severity}] {title}*",
        "attachments": [
            {
                "color": "#FF0000" if severity == "CRITICAL" else "#FF8800",
                "fields": [
                    {"title": "Description", "value": description, "short": False},
                    {"title": "Source IPs", "value": ", ".join(source_ips) or "N/A", "short": True},
                    {"title": "MITRE Tactic", "value": mitre_tactic, "short": True},
                    {"title": "Alert ID", "value": alert.get("alert_id", ""), "short": True},
                    {"title": "Confidence", "value": f"{alert.get('confidence', 0)*100:.1f}%", "short": True},
                ],
            }
        ],
        # Full alert JSON for Splunk/custom endpoints
        "enclivra_alert": alert,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code < 300:
                logger.info(f"Webhook sent for alert {alert.get('alert_id')}")
            else:
                logger.warning(f"Webhook returned {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"Webhook dispatch failed: {exc}")


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
def _send_email(alert: dict[str, Any]) -> None:
    smtp_host = os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("ALERT_SMTP_PORT", "587"))
    smtp_user = os.getenv("ALERT_SMTP_USER", "")
    smtp_pass = os.getenv("ALERT_SMTP_PASS", "")
    email_from = os.getenv("ALERT_EMAIL_FROM", smtp_user)
    email_to = os.getenv("ALERT_EMAIL_TO", "")

    if not all([smtp_user, smtp_pass, email_to]):
        return  # Email not configured — silently skip

    severity = alert.get("severity", "medium").upper()
    title = alert.get("title", "Threat Alert")
    alert_id = alert.get("alert_id", "N/A")
    source_ips = ", ".join(alert.get("source_ips", [])) or "N/A"
    description = alert.get("description", "")
    mitre = alert.get("mitre", {})
    mitre_tactic = mitre.get("tactic", "Unknown")
    confidence = f"{alert.get('confidence', 0)*100:.1f}%"

    html_body = f"""
    <html><body style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:20px">
    <h2 style="color:#ff4444">🚨 ENCLIVRA CRITICAL ALERT</h2>
    <table style="border-collapse:collapse;width:100%">
      <tr><td style="padding:6px;color:#888">Alert ID</td><td style="padding:6px">{alert_id}</td></tr>
      <tr><td style="padding:6px;color:#888">Severity</td><td style="padding:6px;color:#ff4444"><b>{severity}</b></td></tr>
      <tr><td style="padding:6px;color:#888">Title</td><td style="padding:6px">{title}</td></tr>
      <tr><td style="padding:6px;color:#888">Description</td><td style="padding:6px">{description}</td></tr>
      <tr><td style="padding:6px;color:#888">Source IPs</td><td style="padding:6px">{source_ips}</td></tr>
      <tr><td style="padding:6px;color:#888">Confidence</td><td style="padding:6px">{confidence}</td></tr>
      <tr><td style="padding:6px;color:#888">MITRE Tactic</td><td style="padding:6px">{mitre_tactic}</td></tr>
    </table>
    <p style="color:#666;font-size:12px">ENCLIVRA Sealed Enclave Watch — Automated Alert</p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[ENCLIVRA {severity}] {title}"
    msg["From"] = email_from
    msg["To"] = email_to
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(email_from, [email_to], msg.as_string())
        logger.info(f"Email alert sent for {alert_id} to {email_to}")
    except Exception as exc:
        logger.error(f"Email dispatch failed: {exc}")


# ---------------------------------------------------------------------------
# Main dispatch function
# ---------------------------------------------------------------------------
async def dispatch_alert(
    alert: dict[str, Any],
    ws_clients: list[Any] | None = None,
) -> None:
    """
    Dispatch an alert to all configured channels.

    Args:
        alert: Alert dictionary (serialized ThreatAlert + enrichments)
        ws_clients: List of active FastAPI WebSocket connections
    """
    if _is_duplicate(alert):
        logger.debug(f"Dedup suppressed alert {alert.get('alert_id')}")
        return

    severity = alert.get("severity", "medium").lower()

    # 1. WebSocket broadcast to all connected dashboards
    if ws_clients:
        payload = json.dumps({"type": "alert", "data": alert})
        dead = []
        for ws in list(ws_clients):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                ws_clients.remove(ws)
            except ValueError:
                pass

    # 2. Webhook (all severities)
    if os.getenv("ALERT_WEBHOOK_URL"):
        asyncio.create_task(_send_webhook(alert))

    # 3. Email (CRITICAL only, runs in thread to not block event loop)
    if severity == "critical":
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send_email, alert)

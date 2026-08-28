"""
SentinelX Notifier
====================
Sends real notifications (email and/or Slack/Teams) when something
severe enough happens that an analyst shouldn't have to be staring at the
dashboard to find out — and escalates if a CRITICAL alert sits
unacknowledged past its SLA window.

CONFIGURATION (.env) — all optional, each channel activates independently
---------------------------------------------------------------------------
NOTIFY_MIN_SEVERITY   Default CRITICAL. Alerts at or above this severity
                      trigger a notification. (CRITICAL > HIGH > MEDIUM > LOW)

Email (uses smtplib, no extra dependency):
SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS,
SMTP_FROM, SMTP_TO (comma-separated for multiple recipients)
For Gmail: use an App Password, not your normal password — Google blocks
plain SMTP auth with regular account passwords.

Slack:
SLACK_WEBHOOK_URL   An Incoming Webhook URL from a Slack app — see
                    https://api.slack.com/messaging/webhooks

Teams:
TEAMS_WEBHOOK_URL   A Workflow/Incoming Webhook URL from a Teams channel

Escalation:
SLA_CRITICAL_MINUTES   Default 15. If a CRITICAL alert is still OPEN
                       past this many minutes, escalate() sends a second,
                       distinctly-worded notification. Call escalate_check()
                       periodically (main_engine.py runs it in the health
                       monitor loop) — it tracks what's already been
                       escalated so it won't repeat for the same alert.
"""

import os
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

MIN_SEVERITY = os.environ.get("NOTIFY_MIN_SEVERITY", "CRITICAL").strip().upper()
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip("\"'")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or 587)
SMTP_USER = os.environ.get("SMTP_USER", "").strip("\"'")
SMTP_PASS = os.environ.get("SMTP_PASS", "").strip("\"'")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER).strip("\"'")
SMTP_TO   = [x.strip("\"'").strip() for x in os.environ.get("SMTP_TO", "").split(",") if x.strip("\"'").strip()]

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()

SLA_CRITICAL_MINUTES = int(os.environ.get("SLA_CRITICAL_MINUTES", "15") or 15)

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Which alert IDs we've already escalated, so escalate_check() run every
# health-monitor cycle doesn't re-notify for the same still-open alert.
_escalated_ids = set()


def _should_notify(severity: str) -> bool:
    return _SEVERITY_RANK.get((severity or "").upper(), -1) >= _SEVERITY_RANK.get(MIN_SEVERITY, 3)


def send_email(subject: str, text_body: str, html_body: str = None) -> dict:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_TO):
        return {"success": False, "channel": "email", "error": "SMTP not fully configured in .env"}
    try:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        if html_body:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = SMTP_FROM
            msg["To"] = ", ".join(SMTP_TO)
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
        else:
            msg = MIMEText(text_body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = SMTP_FROM
            msg["To"] = ", ".join(SMTP_TO)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
        return {"success": True, "channel": "email"}
    except Exception as e:
        return {"success": False, "channel": "email", "error": str(e)}


def build_alert_email_html(alert: dict) -> str:
    sev = (alert.get("severity") or "CRITICAL").upper()
    event = alert.get("event") or "Security Alert"
    host = alert.get("host") or "UNKNOWN-HOST"
    aid = alert.get("id") or "ALT-00000000"
    score = alert.get("score") or alert.get("vt_score") or 90
    mitre = f"{alert.get('mitre_id','T1003')} — {alert.get('mitre_name','Credential Access')}"
    timestamp = alert.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = alert.get("user") or "system"
    detail = alert.get("detail") or "Suspicious process execution detected."
    auto_resp = alert.get("auto_response", {})
    action = auto_resp.get("action") if isinstance(auto_resp, dict) else "Host isolated from network. Process terminated."
    if not action:
        action = "Host automatically isolated from network.<br>Process terminated.<br>Escalate to Tier 2 immediately."
    else:
        action = action.replace("\n", "<br>")

    sev_bg = "#f43f5e" if sev == "CRITICAL" else "#ff9500" if sev == "HIGH" else "#0a84ff"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>{sev} Alert — SentinelX</title>
</head>
<body style="margin:0;padding:0;background:#eef1f5;-webkit-text-size-adjust:100%;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">{sev} — {event} on {host} — SentinelX&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5;">
    <tr>
      <td align="center" style="padding:20px 12px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 1px 3px rgba(13,27,46,0.08);">

          <!-- Severity band -->
          <tr>
            <td style="background:{sev_bg};padding:16px 22px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:13px;font-weight:700;letter-spacing:.06em;color:#ffffff;">
                    ⚠ {sev} SEVERITY ALERT
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Brand -->
          <tr>
            <td style="padding:18px 22px 0 22px;">
              <span style="font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:13px;font-weight:700;color:#00c896;letter-spacing:.02em;">SentinelX</span>
              <span style="font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:13px;color:#8a97a8;"> &middot; SOC Platform</span>
            </td>
          </tr>

          <!-- Event title -->
          <tr>
            <td style="padding:10px 22px 4px 22px;">
              <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:19px;font-weight:700;color:#0d1b2e;line-height:1.35;">{event}</span>
            </td>
          </tr>

          <!-- Metadata -->
          <tr>
            <td style="padding:6px 22px 0 22px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f5;">
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#8a97a8;margin-bottom:3px;">Alert ID</span>
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:15px;font-weight:600;color:#0d1b2e;">{aid}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f5;">
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#8a97a8;margin-bottom:3px;">Hostname</span>
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:15px;font-weight:600;color:#0d1b2e;">{host}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f5;">
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#8a97a8;margin-bottom:3px;">Threat Score</span>
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:15px;font-weight:600;color:#f43f5e;">{score}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f5;">
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#8a97a8;margin-bottom:3px;">MITRE ATT&CK</span>
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:15px;font-weight:600;color:#0d1b2e;">{mitre}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f5;">
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#8a97a8;margin-bottom:3px;">Triggered</span>
            <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:15px;font-weight:600;color:#0d1b2e;">{timestamp} &middot; user {user}</span>
          </td>
        </tr>
                
        <tr><td style="padding:14px 0 0 0;">
          <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#8a97a8;margin-bottom:6px;">Detail</span>
          <div style="font-family:'JetBrains Mono',Consolas,Menlo,monospace;font-size:12.5px;line-height:1.6;color:#40506a;background:#f5f7fa;border-radius:8px;padding:12px 14px;word-break:break-word;">{detail}</div>
        </td></tr>
              </table>
            </td>
          </tr>

          <!-- Recommended action -->
          <tr>
            <td style="padding:16px 22px 0 22px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fff7ed;border-left:3px solid {sev_bg};border-radius:8px;">
                <tr>
                  <td style="padding:12px 14px;">
                    <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#92511b;margin-bottom:5px;">Recommended Action</span>
                    <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:13.5px;line-height:1.55;color:#5c3a10;">{action}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td style="padding:20px 22px 22px 22px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" bgcolor="#00c896" style="border-radius:9px;">
                    <a href="http://localhost:5000/alert/{aid}" target="_blank"
                       style="display:block;padding:14px 20px;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:15px;font-weight:700;color:#04211a;text-decoration:none;">
                      View in Dashboard →
                    </a>
                  </td>
                </tr>
              </table>
              <div style="text-align:center;margin-top:10px;">
                <a href="http://localhost:5000/alert/{aid}" style="font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11.5px;color:#8a97a8;word-break:break-all;">http://localhost:5000/alert/{aid}</a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:16px 22px;background:#f8f9fb;border-top:1px solid #eef1f5;">
              <span style="display:block;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:11px;line-height:1.6;color:#9aa5b3;">
                Automated alert from SentinelX. To change who receives these, update ALERT_EMAIL_RECIPIENT / NOTIFY_MIN_SEVERITY in .env.
              </span>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def notify_alert(alert: dict) -> list:
    """
    Fire whichever channels are configured if `alert`'s severity meets
    NOTIFY_MIN_SEVERITY. Returns a list of per-channel result dicts.
    """
    if not _should_notify(alert.get("severity")):
        return []

    subject = f"[SentinelX] {alert.get('severity','?')} — {alert.get('event','Alert')} on {alert.get('host','?')}"
    text_body = (
        f"Severity : {alert.get('severity','?')}\n"
        f"Event    : {alert.get('event','?')}\n"
        f"Host     : {alert.get('host','?')}\n"
        f"User     : {alert.get('user','?')}\n"
        f"Time     : {alert.get('timestamp','?')}\n"
        f"MITRE    : {alert.get('mitre_id','?')} - {alert.get('mitre_name','?')}\n\n"
        f"{alert.get('detail','')}"
    )
    html_body = build_alert_email_html(alert)

    results = []
    if SMTP_HOST:
        results.append(send_email(subject, text_body, html_body))
    if SLACK_WEBHOOK_URL:
        results.append(send_slack(f"*{subject}*\n```{text_body}```"))
    if TEAMS_WEBHOOK_URL:
        results.append(send_teams(f"**{subject}**\n\n{text_body}"))
    return results


def escalate_check(alerts: list):
    """
    Call periodically (main_engine.py's health monitor does this every
    cycle). Sends a distinct escalation notification for any CRITICAL
    alert still OPEN past SLA_CRITICAL_MINUTES that hasn't already been
    escalated this run.
    """
    now = datetime.now()
    for a in alerts:
        if a.get("severity") != "CRITICAL" or a.get("status") != "OPEN":
            continue
        aid = a.get("id")
        if not aid or aid in _escalated_ids:
            continue
        try:
            ts = datetime.strptime(a.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if (now - ts).total_seconds() < SLA_CRITICAL_MINUTES * 60:
            continue

        _escalated_ids.add(aid)
        subject = f"[SentinelX ESCALATION] CRITICAL alert unacknowledged {SLA_CRITICAL_MINUTES}+ min"
        body = (f"Alert {aid} on {a.get('host','?')} has been OPEN for over "
                f"{SLA_CRITICAL_MINUTES} minutes with no status change.\n\n"
                f"Event: {a.get('event','?')}\nDetail: {a.get('detail','')}")
        if SMTP_HOST:
            send_email(subject, body)
        if SLACK_WEBHOOK_URL:
            send_slack(f"🚨 *{subject}*\n{body}")
        if TEAMS_WEBHOOK_URL:
            send_teams(f"🚨 **{subject}**\n\n{body}")
        if len(_escalated_ids) > 5000:  # bounded, same spirit as every other in-memory cache in this app
            _escalated_ids.clear()

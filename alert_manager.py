#!/usr/bin/env python3
import json
import urllib.request
from datetime import datetime

TELEGRAM_TOKEN   = "8418279957:AAEfM246y0vWrGAIfxNJ-c6WwZ-X9feUxnI"
TELEGRAM_CHAT_ID = "8728674934"
ALERT_LOG        = "/var/log/zt-alerts.log"

ALERT_SCAN_DETECTED = "SCAN_DETECTED"
ALERT_ATTACKER      = "EXTERNAL_ATTACKER"
ALERT_QUARANTINE    = "DEVICE_QUARANTINED"
ALERT_MAC_CHANGE    = "MAC_SPOOFING"
ALERT_SCORE_DROP    = "SCORE_DROP"
ALERT_RESTORED      = "DEVICE_RESTORED"
ALERT_EAST_WEST     = "EAST_WEST_ATTEMPT"

ICONS = {
    "SCAN_DETECTED"    : "🔍",
    "EXTERNAL_ATTACKER": "🚨",
    "DEVICE_QUARANTINED": "🔒",
    "MAC_SPOOFING"     : "⚠️",
    "SCORE_DROP"       : "📉",
    "DEVICE_RESTORED"  : "✅",
    "EAST_WEST_ATTEMPT": "🔀",
}

def _write_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        print(f"Log write failed: {e}")

def _send_telegram(message):
    try:
        url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = json.dumps({
            "chat_id"   : TELEGRAM_CHAT_ID,
            "text"      : message,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        _write_log(f"[TELEGRAM ERROR] {e}")
        return False

def send_alert(alert_type, details):
    icon      = ICONS.get(alert_type, "INFO")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if alert_type == ALERT_QUARANTINE:
        message = (
            f"{icon} DEVICE QUARANTINED\n"
            f"Device : {details.get('device')}\n"
            f"IP     : {details.get('ip')}\n"
            f"Reason : {details.get('reason')}\n"
            f"Time   : {timestamp}"
        )
    elif alert_type == ALERT_ATTACKER:
        message = (
            f"{icon} EXTERNAL ATTACKER DETECTED\n"
            f"Attacker : {details.get('attacker')}\n"
            f"Targets  : {details.get('targets')} IoT devices\n"
            f"Time     : {timestamp}"
        )
    elif alert_type == ALERT_EAST_WEST:
        message = (
            f"{icon} EAST-WEST ATTACK DETECTED\n"
            f"Source   : {details.get('src_device')} ({details.get('src_ip')})\n"
            f"Target   : {details.get('dst_ip')}\n"
            f"Attempts : {details.get('attempts')} packets blocked\n"
            f"Time     : {timestamp}"
        )
    else:
        message = f"{icon} {alert_type}\n{json.dumps(details)}\nTime: {timestamp}"

    _write_log(message.replace("\n", " | "))
    _send_telegram(message)

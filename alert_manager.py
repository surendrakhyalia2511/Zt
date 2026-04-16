#!/usr/bin/env python3
"""
alert_manager.py
ZeroShield Gateway — Alert Manager
Reads credentials from .env (path via SK_HOME env var)
"""
import json
import urllib.request
import sys
import os
from datetime import datetime

_SK_HOME = os.environ.get("SK_HOME", "/home/sk")
sys.path.insert(0, _SK_HOME)
from env_loader import env

TELEGRAM_TOKEN   = env("TELEGRAM_TOKEN",   "")
TELEGRAM_CHAT_ID = env("TELEGRAM_CHAT_ID", "")
TELEGRAM_TIMEOUT = int(env("TELEGRAM_TIMEOUT", "5"))
ALERT_LOG        = env("ALERT_LOG", "/var/log/zt-alerts.log")

SCORE_SOFT_PENALTY = int(env("SCORE_SOFT_PENALTY", "10"))
SCORE_HARD_PENALTY = int(env("SCORE_HARD_PENALTY", "35"))

ALERT_SCAN_DETECTED = "SCAN_DETECTED"
ALERT_ATTACKER      = "EXTERNAL_ATTACKER"
ALERT_QUARANTINE    = "DEVICE_QUARANTINED"
ALERT_MAC_CHANGE    = "MAC_SPOOFING"
ALERT_SCORE_DROP    = "SCORE_DROP"
ALERT_RESTORED      = "DEVICE_RESTORED"
ALERT_EAST_WEST     = "EAST_WEST_ATTEMPT"
ALERT_JOINED        = "DEVICE_JOINED"
ALERT_LEFT          = "DEVICE_LEFT"

ICONS = {
    "SCAN_DETECTED"    : "🔍",
    "EXTERNAL_ATTACKER": "🚨",
    "DEVICE_QUARANTINED": "🔒",
    "MAC_SPOOFING"     : "⚠️",
    "SCORE_DROP"       : "📉",
    "DEVICE_RESTORED"  : "✅",
    "EAST_WEST_ATTEMPT": "🔀",
    "DEVICE_JOINED"    : "🟢",
    "DEVICE_LEFT"      : "🔴",
}

def _write_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        print(f"Log write failed: {e}")

def _send_telegram(message):
    """Send Telegram alert in background thread — never blocks the controller."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    import threading
    def _send():
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
            urllib.request.urlopen(req, timeout=TELEGRAM_TIMEOUT)
        except Exception as e:
            _write_log(f"[TELEGRAM ERROR] {e}")
    t = threading.Thread(target=_send, daemon=True)
    t.start()
    return True

def send_alert(alert_type, details):
    icon      = ICONS.get(alert_type, "ℹ️")
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
    elif alert_type == ALERT_RESTORED:
        message = (
            f"{icon} DEVICE RESTORED\n"
            f"Device : {details.get('device')}\n"
            f"IP     : {details.get('ip')}\n"
            f"Action : Returned to IoT LAN — monitoring resumed\n"
            f"Time   : {timestamp}"
        )
    elif alert_type == ALERT_SCORE_DROP:
        zone = details.get("zone", "")
        if zone == "BUFFER":
            message = (
                f"⚠️ RATE SOFT WARNING\n"
                f"Device  : {details.get('device')}\n"
                f"IP      : {details.get('ip')}\n"
                f"Details : {details.get('message', '')}\n"
                f"Action  : Score -{SCORE_SOFT_PENALTY} | Still TRUSTED | Auto-recovers\n"
                f"Time    : {timestamp}"
            )
        elif zone == "EXCEEDED":
            message = (
                f"🚨 RATE HARD VIOLATION\n"
                f"Device  : {details.get('device')}\n"
                f"IP      : {details.get('ip')}\n"
                f"Details : {details.get('message', '')}\n"
                f"Action  : Score -{SCORE_HARD_PENALTY} | QUARANTINE triggered\n"
                f"Time    : {timestamp}"
            )
        elif zone == "RECOVERED":
            message = (
                f"✅ RATE RECOVERED\n"
                f"Device  : {details.get('device')}\n"
                f"IP      : {details.get('ip')}\n"
                f"Action  : Penalty cleared | Score restored\n"
                f"Time    : {timestamp}"
            )
        else:
            message = f"📉 SCORE DROP\n{json.dumps(details)}\nTime: {timestamp}"

    elif alert_type == "DEVICE_JOINED":
        message = (
            f"🟢 NEW DEVICE ON NETWORK\n"
            f"Device : {details.get('device')}\n"
            f"IP     : {details.get('ip')}\n"
            f"Action : Fingerprinting and monitoring started\n"
            f"Time   : {timestamp}"
        )
    elif alert_type == "DEVICE_LEFT":
        message = (
            f"🔴 DEVICE LEFT NETWORK\n"
            f"Device : {details.get('device')}\n"
            f"IP     : {details.get('ip')}\n"
            f"Action : Marked inactive — rate rules removed\n"
            f"Time   : {timestamp}"
        )
    elif alert_type == "WHITELIST_ADDED":
        message = (
            f"📋 WHITELIST RULE ADDED\n"
            f"From   : {details.get('src')}\n"
            f"To     : {details.get('dst')}\n"
            f"Note   : {details.get('note', '')}\n"
            f"Time   : {timestamp}"
        )
    else:
        message = f"ℹ️ {alert_type}\n{json.dumps(details)}\nTime: {timestamp}"

    _write_log(message.replace("\n", " | "))
    _send_telegram(message)


def send_attack_summary(attacker_ip, target_count, quarantined_devices):
    """
    Send ONE combined Telegram message for an attack + all resulting quarantines.
    quarantined_devices: list of {"device": name, "ip": ip, "reason": reason}
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"🚨 ATTACK SUMMARY",
        f"Attacker  : {attacker_ip}",
        f"Targets   : {target_count} IoT devices scanned",
        f"Time      : {timestamp}",
        f"",
        f"🔒 Devices Isolated ({len(quarantined_devices)}):",
    ]
    for d in quarantined_devices:
        lines.append(f"  • {d['device']} ({d['ip']})")
        reason = d.get('reason', '')
        if reason:
            lines.append(f"    Reason: {reason[:80]}")
    message = "\n".join(lines)
    _write_log(message.replace("\n", " | "))
    _send_telegram(message)

#!/usr/bin/env python3
"""
logger.py
Zero Trust IoT Gateway — Logging and History Persistence
"""

import json
import os
from datetime import datetime

LOG_FILE     = "/var/log/zt-controller.log"
HISTORY_FILE = "/home/sk/device_history.json"


def log(msg, level="INFO"):
    icons = {"INFO": "ℹ️ ", "WARN": "⚠️ ", "ALERT": "🚨", "ACTION": "🔒"}
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {icons.get(level, '')} [{level}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[LOG ERROR] {e}")


def save_history(dh):
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(dh, f, indent=2)
    except Exception as e:
        log(f"History save failed: {e}", "WARN")


def load_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                data = json.load(f)
            log(f"Loaded history for {len(data)} devices")
            return data
    except Exception as e:
        log(f"History load failed: {e}", "WARN")
    return {}

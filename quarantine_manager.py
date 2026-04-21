#!/usr/bin/env python3
import subprocess
import sys, os
sys.path.insert(0, os.environ.get("SK_HOME", "/home/sk"))
from env_loader import env
from logger import log
import alert_manager      as am
import rate_limit_manager as rl


def quarantine_device(container, ip, reason, device_type, dh, key):
    log(f"QUARANTINING {container} ({ip}) — {reason}", "ACTION")

    r = subprocess.run(
        ["bash", env("QUARANTINE_SH", "/home/sk/quarantine_device.sh"), container, ip],
        capture_output=True, text=True
    )
    log(f"Quarantine result: {r.stdout.strip()}", "ACTION")
    if r.stderr.strip():
        log(f"Quarantine stderr: {r.stderr.strip()}", "WARN")

    subprocess.run(["nft", "flush", "chain", "ip", "raw", "PREROUTING"], capture_output=True)
    rl.remove_limit(container, ip, device_type)

    dh[key].update({
        "quarantined_before": True,
        "quarantine_count":   dh[key].get("quarantine_count", 0) + 1,
        "quarantined":        True,
        "scanning":           False,
        "under_attack":       False,
        "east_west":          False,
        "rl_penalty":         0,
        "rl_applied":         False,
        "restore_alert_sent": False,
    })

    am.send_alert(am.ALERT_QUARANTINE, {"device": container, "ip": ip, "reason": reason})

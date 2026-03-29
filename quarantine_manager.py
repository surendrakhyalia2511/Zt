#!/usr/bin/env python3
"""
quarantine_manager.py
Zero Trust IoT Gateway — Quarantine and Restore Operations

BUG FIX: quarantine_device.sh was called without the IP argument.
dashboard_api.py calls: subprocess.run(["bash", QUARANTINE_SH, name, ip])
quarantine_manager.py was calling: subprocess.run([QUARANTINE_SH, container])
Now both pass name + ip consistently.
"""
import subprocess
from logger import log
import alert_manager      as am
import rate_limit_manager as rl


def quarantine_device(container, ip, reason, device_type, dh, key):
    """
    Move a device to the quarantine network.

    Steps:
      1. Run quarantine_device.sh <container> <ip>
      2. Remove iptables rate limit rules for this device
      3. Update device history flags
      4. Send Telegram + log alert

    Args:
        container   : Docker container name
        ip          : Current IP on IoT LAN
        reason      : Human-readable quarantine reason
        device_type : Classified device type
        dh          : device_history dict (modified in place)
        key         : History key (= container name)
    """
    log(f"QUARANTINING {container} ({ip}) — {reason}", "ACTION")

    # BUG FIX: was missing ip arg — script only got container name
    # quarantine_device.sh needs both $1=container and $2=ip
    r = subprocess.run(
        ["bash", "/home/sk/quarantine_device.sh", container, ip],
        capture_output=True, text=True
    )
    log(f"Quarantine result: {r.stdout.strip()}", "ACTION")
    if r.stderr.strip():
        log(f"Quarantine stderr: {r.stderr.strip()}", "WARN")

    # Flush nft raw PREROUTING — avoids Docker DROP rules blocking monitoring
    subprocess.run(
        ["nft", "flush", "chain", "ip", "raw", "PREROUTING"],
        capture_output=True
    )

    # Remove rate limit rules — device is leaving IoT LAN
    rl.remove_limit(container, ip, device_type)

    # Update history — reset all behavioral flags
    dh[key].update({
        "quarantined_before": True,
        "quarantine_count"  : dh[key].get("quarantine_count", 0) + 1,
        "quarantined"       : True,
        "scanning"          : False,
        "under_attack"      : False,
        "east_west"         : False,
        "rl_penalty"        : 0,
        "rl_applied"        : False,      # re-apply rules when restored
        "restore_alert_sent": False,      # reset so next restore fires alert
    })

    am.send_alert(am.ALERT_QUARANTINE, {
        "device": container,
        "ip"    : ip,
        "reason": reason,
    })

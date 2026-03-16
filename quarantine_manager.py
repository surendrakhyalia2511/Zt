#!/usr/bin/env python3
"""
quarantine_manager.py
Zero Trust IoT Gateway — Quarantine and Restore Operations
"""

import subprocess
from logger import log
import alert_manager      as am
import rate_limit_manager as rl


def quarantine_device(container, ip, reason, device_type, dh, key):
    """
    Move a device to the quarantine network.

    Steps:
      1. Run quarantine_device.sh (docker network disconnect/connect)
      2. Flush nft raw PREROUTING to clear stale rules
      3. Remove iptables rate limit rules for this device
      4. Update device history flags
      5. Send Telegram + log alert

    Args:
        container   : Docker container name
        ip          : Current IP on IoT LAN
        reason      : Human-readable quarantine reason
        device_type : Classified device type
        dh          : device_history dict (modified in place)
        key         : History key (= container name)
    """
    log(f"QUARANTINING {container} ({ip}) — {reason}", "ACTION")

    r = subprocess.run(
        ["/home/sk/quarantine_device.sh", container],
        capture_output=True, text=True
    )
    log(f"Quarantine result: {r.stdout.strip()}", "ACTION")

    # Flush nft raw PREROUTING — avoids Docker DROP rules blocking monitoring
    subprocess.run(
        ["nft", "flush", "chain", "ip", "raw", "PREROUTING"],
        capture_output=True
    )

    # Remove rate limit mark rules — device is leaving IoT LAN
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
        "rl_applied"        : False,   # re-apply rules when restored
    })

    am.send_alert(am.ALERT_QUARANTINE, {
        "device": container,
        "ip"    : ip,
        "reason": reason,
    })

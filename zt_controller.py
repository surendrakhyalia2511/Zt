#!/usr/bin/env python3
"""
zt_controller.py
Zero Trust Smart Home IoT Gateway — Master Controller

Architecture (Option 5 — Separate Monitor Process):
  behavior_monitor.sh  → runs continuously in background
                          captures ens37 + docker-iot every 2 seconds
                          writes SCAN and EAST_WEST events to shared file

  zt_controller.py     → reads events from shared file each cycle
                          handles scoring, rate limits, quarantine decisions

This means attacks are detected within 2 seconds (monitor cycle)
regardless of the controller's 5-second evaluation cycle.

Modules:
  logger.py             — logging, history load/save
  discovery.py          — arp-scan, nmap fingerprint, container name lookup
  scoring.py            — trust score calculation
  traffic_monitor.py    — tcpdump parallel capture (still used for connection_map)
  quarantine_manager.py — quarantine device operation
  event_reader.py       — read events from behavior_monitor.sh
  alert_manager.py      — Telegram + log alerts
  rate_limit_manager.py — iptables MARK rules, zone evaluation
"""

import time
import subprocess
import sys
import os

sys.path.insert(0, '/home/sk')

from logger             import log, save_history, load_history
from discovery          import discover_devices, fingerprint_device, get_container_name
from scoring            import calculate_trust_score, get_status, SCORE_THRESHOLD
from traffic_monitor    import capture_both
from quarantine_manager import quarantine_device
from event_reader       import read_and_clear, merge_scan_events, merge_east_west_events
import alert_manager      as am
import rate_limit_manager as rl

# ============================================================
# CONFIGURATION
# ============================================================
IOT_NET            = "192.168.20"
TRUSTED_NET        = "192.168.10"
QUARANTINE_NET     = "192.168.30"
SCAN_THRESHOLD     = 3    # unique dst IPs = scan
MONITOR_INTERVAL   = 5    # controller evaluation cycle seconds
DISCOVERY_INTERVAL = 3    # re-run arp-scan every N cycles
SLEEP_BETWEEN      = 2    # seconds between cycles

BEHAVIOR_MONITOR   = "/home/sk/behavior_monitor.sh"
EVENTS_FILE        = "/var/run/zt-monitor-events.jsonl"


# ============================================================
# START BACKGROUND MONITOR
# ============================================================
def start_monitor():
    """
    Launch behavior_monitor.sh as a background process.
    Returns the Popen object so we can check/restart it.
    """
    log("Starting background behavioral monitor...")
    try:
        proc = subprocess.Popen(
            ["sudo", "bash", BEHAVIOR_MONITOR],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setpgrp   # separate process group
        )
        log(f"Behavioral monitor started (PID={proc.pid})")
        return proc
    except Exception as e:
        log(f"Failed to start behavioral monitor: {e}", "WARN")
        return None


def ensure_monitor(proc):
    """
    Check if monitor is still running. Restart if crashed.
    """
    if proc is None or proc.poll() is not None:
        log("Behavioral monitor stopped — restarting...", "WARN")
        return start_monitor()
    return proc


# ============================================================
# MAIN CONTROLLER LOOP
# ============================================================
def main():
    log("=" * 60)
    log("Zero Trust IoT Gateway Controller Started")
    log("=" * 60)
    log("Mode: Option 5 — Separate background behavioral monitor")

    dh            = load_history()
    known_devices = {}
    cycle         = 0

    # Apply rate limits for known non-quarantined devices on startup
    if dh:
        rl.apply_all(dh)
        rl.status()

    # Start background behavioral monitor
    monitor_proc = start_monitor()
    time.sleep(1)   # give monitor a moment to initialize

    while True:
        cycle += 1
        log(f"\n{'─'*60}")
        log(f"--- Monitoring Cycle {cycle} ---")

        # ── Ensure monitor is alive ───────────────────────────
        monitor_proc = ensure_monitor(monitor_proc)

        # ── Discovery ─────────────────────────────────────────
        if cycle == 1 or cycle % DISCOVERY_INTERVAL == 0:
            known_devices = discover_devices()
        else:
            log(f"Using cached device list ({len(known_devices)} devices)")

        # ── Read events from background monitor ───────────────
        # behavior_monitor.sh has been running continuously since
        # last cycle — collect all events it detected
        scan_events, east_west_events = read_and_clear()

        scan_map      = merge_scan_events(scan_events)
        east_west_map = merge_east_west_events(east_west_events)

        log(f"Monitor events: {len(scan_events)} scan, "
            f"{len(east_west_events)} east-west")

        # ── Also run controller's own tcpdump for connection_map
        # This gives us per-device connection counts for scoring
        # Runs in parallel with the monitor (different interface focus)
        connection_map, _ = capture_both(MONITOR_INTERVAL)

        # ── Process scan events from monitor ──────────────────
        attacked_devices = set()
        for attacker_ip, targets in scan_map.items():
            count = len(targets)
            log(f"SCANNING DETECTED: {attacker_ip} contacted "
                f"{count} IoT devices", "ALERT")
            if attacker_ip.startswith(TRUSTED_NET):
                log(f"EXTERNAL ATTACKER: {attacker_ip} scanning IoT network!", "ALERT")
                am.send_alert(am.ALERT_ATTACKER, {
                    "attacker": attacker_ip,
                    "targets" : count
                })
            for dst_ip in targets:
                if dst_ip.startswith(IOT_NET):
                    attacked_devices.add(dst_ip)

        # ── Process east-west events from monitor ─────────────
        for ew_src, ew_dsts in east_west_map.items():
            ew_container = get_container_name(ew_src)
            if not ew_container or ew_container == ew_src:
                continue
            log(f"EAST-WEST DETECTED: {ew_container} ({ew_src}) "
                f"→ tried to reach {len(ew_dsts)} IoT device(s): "
                f"{', '.join(ew_dsts)}", "ALERT")
            am.send_alert(am.ALERT_EAST_WEST, {
                "src_device": ew_container,
                "src_ip"    : ew_src,
                "dst_ip"    : ", ".join(ew_dsts),
                "attempts"  : len(ew_dsts),
            })
            if ew_container in dh:
                dh[ew_container]["east_west"] = True

        # ── Rate limit evaluation ─────────────────────────────
        mark_counts = rl.read_mark_counts()

        for m_ip, m_data in mark_counts.items():
            d_container = get_container_name(m_ip)
            if not d_container or d_container == m_ip:
                continue

            d_key  = d_container
            d_type = dh.get(d_key, {}).get("device_type", "Unknown IoT Device")

            zone, penalty, recovered, msg = rl.evaluate(
                d_container, m_ip, d_type, m_data
            )

            dh.setdefault(d_key, {})["rl_penalty"] = penalty

            if zone == "SOFT":
                log(f"RATE BUFFER   | {d_container:15} | {msg}", "WARN")
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": m_ip,
                    "zone": "BUFFER", "penalty": penalty, "message": msg
                })
            elif zone == "HARD":
                log(f"RATE EXCEEDED | {d_container:15} | {msg}", "ALERT")
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": m_ip,
                    "zone": "EXCEEDED", "penalty": penalty, "message": msg
                })

            if recovered:
                log(f"RATE RECOVERED| {d_container:15} | back to normal — penalty cleared")
                dh[d_key]["rl_penalty"] = 0
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": m_ip,
                    "zone": "RECOVERED",
                    "message": "Rate returned to normal — penalty removed"
                })

        rl.reset_counters()

        # ── Per-device evaluation ─────────────────────────────
        for ip, info in known_devices.items():
            container = get_container_name(ip)
            if not container or container == ip:
                continue

            key = container

            # ── New device ────────────────────────────────────
            if key not in dh:
                ports, dev_type = fingerprint_device(ip)
                log(f"Fingerprinted: {container} ({ip}) → {ports} → {dev_type}")

                if ip.startswith(IOT_NET):
                    rl.apply_conn_limit(container, ip, dev_type)

                dh[key] = {
                    "container"         : container,
                    "last_ip"           : ip,
                    "mac"               : info["mac"],
                    "vendor"            : info["vendor"],
                    "device_type"       : dev_type,
                    "open_ports"        : ports,
                    "scanning"          : False,
                    "connections"       : 0,
                    "under_attack"      : False,
                    "east_west"         : False,
                    "quarantined_before": False,
                    "quarantined"       : False,
                    "quarantine_count"  : 0,
                    "rl_penalty"        : 0,
                    "rl_applied"        : ip.startswith(IOT_NET),
                }

            else:
                # ── Update live fields ────────────────────────
                dh[key]["last_ip"]     = ip
                dh[key]["mac"]         = info["mac"]
                dh[key]["quarantined"] = ip.startswith(QUARANTINE_NET)

                # Re-apply rate limit if missing
                if ip.startswith(IOT_NET) and not dh[key].get("rl_applied", False):
                    log(f"Re-applying rate limit: {container} ({ip})")
                    rl.apply_conn_limit(
                        container, ip,
                        dh[key].get("device_type", "Unknown IoT Device")
                    )
                    dh[key]["rl_applied"] = True

            # ── Behavioral flags ──────────────────────────────
            unique_dests = len(connection_map.get(ip, set()))
            dh[key]["connections"]  = unique_dests
            dh[key]["under_attack"] = (ip in attacked_devices)

            # East-west flag — set by monitor events, cleared if not seen
            if ip in east_west_map:
                dh[key]["east_west"] = True
            elif not dh[key].get("quarantined", False):
                # Only clear if device is on IoT LAN — quarantined devices
                # keep their east_west flag until manually restored
                dh[key]["east_west"] = False

            if unique_dests >= SCAN_THRESHOLD:
                dh[key]["scanning"] = True
                log(f"IOT SCANNING: {container} ({ip}) → {unique_dests} targets", "ALERT")
            else:
                dh[key]["scanning"] = False

            if ip in attacked_devices:
                log(f"TARGET: {container} ({ip}) "
                    f"[{dh[key]['device_type']}] being scanned", "WARN")

            # ── Active connection check ───────────────────────
            if not dh[key].get("quarantined", False):
                exceeded, conn_count, conn_limit, conn_msg = \
                    rl.check_active_connections(
                        container, ip,
                        dh[key].get("device_type", "Unknown IoT Device")
                    )
                if exceeded:
                    log(f"ACTIVE CONN EXCEEDED: {container} ({ip}) "
                        f"— {conn_count}/{conn_limit}", "ALERT")
                    am.send_alert(am.ALERT_QUARANTINE, {
                        "device": container, "ip": ip, "reason": conn_msg
                    })
                    quarantine_device(
                        container, ip, conn_msg,
                        dh[key].get("device_type", "Unknown IoT Device"),
                        dh, key
                    )
                    continue

            # ── Trust score ───────────────────────────────────
            score, reasons = calculate_trust_score(dh[key])
            status   = get_status(score, dh[key].get("quarantined", False))
            zone_tag = "QUAR" if ip.startswith(QUARANTINE_NET) else "IoT "
            dt_short = dh[key].get("device_type", "Unknown")[:18]

            log(f"{container:15} | {ip:15} | [{zone_tag}] "
                f"{dt_short:18} | Score: {score:3} | {status}")

            # ── Auto quarantine ───────────────────────────────
            if score < SCORE_THRESHOLD:
                if not dh[key].get("quarantined", False):
                    quarantine_device(
                        container, ip,
                        f"Trust score {score} | {'; '.join(reasons)}",
                        dh[key].get("device_type", "Unknown IoT Device"),
                        dh, key
                    )

        # ── End of cycle ──────────────────────────────────────
        save_history(dh)
        log(f"Cycle {cycle} complete. {len(known_devices)} devices. History saved.")
        log(f"Sleeping {SLEEP_BETWEEN}s...")
        time.sleep(SLEEP_BETWEEN)


if __name__ == "__main__":
    main()

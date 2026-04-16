#!/usr/bin/env python3
"""
zt_controller.py
Zero Trust Smart Home IoT Gateway — Master Controller

RATE LIMIT FIXES in this version (on top of previous east-west fixes):

  FIX A — IP→container lookup in rate-limit loop now uses device_history,
           not docker inspect.

           Old code called get_container_name(d_ip) for every dropped-packet
           IP, which spawned a subprocess docker network inspect on each call.
           If docker inspect was slow, timed out, or the container had just
           moved networks, it returned the raw IP string → the guard
           `if not container or container == ip: continue` silently skipped
           the device → rate limit violations were NEVER acted on.

           Fix: build a reverse { ip: container_name } map directly from dh
           at the top of each cycle. O(1) lookup, no subprocess, always
           consistent with what the iptables rules were installed against.

  FIX B — apply_all() on startup is called BEFORE per-device discovery,
           so it uses the IPs stored in device_history.json. If a container
           restarted and got a new IP since the last save, the iptables rule
           would be installed against the OLD IP. Added a post-discovery
           rule sync: after known_devices is populated, any IoT device whose
           current IP differs from dh["last_ip"] gets its old rule removed
           and a new rule installed against the live IP.

  FIX C — HARD rate violation now immediately triggers quarantine in the
           rate-limit evaluation block, the same way east-west does.
           Previously it only set rl_penalty=35 and waited for the scoring
           loop to notice the score had dropped below threshold — but if the
           controller cycle was short or the device wasn't in known_devices
           yet, quarantine never fired.
"""

import time
import subprocess
import sys
import os
import json

sys.path.insert(0, os.environ.get("APP_PATH", "/home/sk"))

from env_loader import env
HEARTBEAT_FILE = env("HEARTBEAT_FILE", "/var/run/zt-heartbeat")

from logger             import log, save_history, load_history
from datetime           import datetime
from discovery          import discover_devices, fingerprint_device, get_container_name
from scoring            import calculate_trust_score, get_status, persist_score, SCORE_THRESHOLD
from traffic_monitor    import capture_both
from quarantine_manager import quarantine_device
from event_reader       import read_and_clear, merge_scan_events, merge_east_west_events
import alert_manager      as am
import rate_limit_manager as rl

# ============================================================
# CONFIGURATION
# ============================================================
IOT_NET            = env("IOT_NET",            "192.168.20")
TRUSTED_NET        = env("TRUSTED_NET",        "192.168.10")
QUARANTINE_NET     = env("QUARANTINE_NET",     "192.168.30")
SCAN_THRESHOLD     = int(env("SCAN_THRESHOLD",     "3"))
MONITOR_INTERVAL   = int(env("MONITOR_INTERVAL",   "2"))
DISCOVERY_INTERVAL = int(env("DISCOVERY_INTERVAL", "3"))
SLEEP_BETWEEN      = int(env("SLEEP_BETWEEN",      "1"))

BEHAVIOR_MONITOR = env("BEHAVIOR_MONITOR", "/home/sk/behavior_monitor.sh")
EVENTS_FILE      = env("EVENTS_FILE",      "/var/run/zt-monitor-events.jsonl")
DEVICE_HISTORY   = env("DEVICE_HISTORY",   "/home/sk/device_history.json")


def start_monitor():
    log("Starting background behavioral monitor...")
    try:
        proc = subprocess.Popen(
            ["sudo", "bash", BEHAVIOR_MONITOR],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setpgrp
        )
        log(f"Behavioral monitor started (PID={proc.pid})")
        return proc
    except Exception as e:
        log(f"Failed to start behavioral monitor: {e}", "WARN")
        return None


def ensure_monitor(proc):
    if proc is None or proc.poll() is not None:
        log("Behavioral monitor stopped — restarting...", "WARN")
        return start_monitor()
    return proc


def build_ip_map(dh):
    """
    Build a reverse { ip_address: container_name } map from device_history.

    FIX A: Used in the rate-limit evaluation loop instead of calling
    get_container_name(ip) (which spawns docker inspect subprocesses and
    silently returns the raw IP on failure, causing the loop guard
    `container == ip` to skip every device).

    This map is always consistent with the IPs that iptables rules were
    installed against, because both originate from device_history.
    """
    return {
        info["last_ip"]: name
        for name, info in dh.items()
        if info.get("last_ip")
    }


def sync_rate_limit_rules(dh, known_devices):
    """
    FIX B: After discovery, compare each device's live IP (from known_devices)
    against the IP stored in device_history. If they differ, the iptables
    hashlimit rule is still bound to the old IP — remove it and install a
    new one against the current IP.

    This handles container restarts that cause IP reassignment between
    controller restarts.
    """
    iot_prefix = IOT_NET + "."
    for ip, info in known_devices.items():
        if not ip.startswith(iot_prefix):
            continue
        container = get_container_name(ip)
        if not container or container == ip:
            continue
        if container not in dh:
            continue
        old_ip = dh[container].get("last_ip", "")
        if old_ip and old_ip != ip and not dh[container].get("quarantined", False):
            dev_type = dh[container].get("device_type", "Unknown IoT Device")
            log(f"IP changed: {container} {old_ip} → {ip}, re-syncing iptables rule")
            rl.remove_limit(container, old_ip, dev_type)
            rl.apply_hard_limit(container, ip, dev_type)
            dh[container]["last_ip"]   = ip
            dh[container]["rl_applied"] = True


def main():
    log("=" * 60)
    log("Zero Trust IoT Gateway Controller Started")
    log("=" * 60)

    dh               = load_history()
    known_devices    = {}
    cycle            = 0
    force_rediscovery = False   # set True after quarantine/restore to trigger immediate rediscovery
    prev_iot_set     = set()    # track device IPs seen last cycle for join/leave detection

    if dh:
        rl.apply_all(dh)
        rl.status()

    monitor_proc = start_monitor()
    time.sleep(1)

    while True:
        cycle += 1
        log(f"\n{'─'*60}")
        log(f"--- Monitoring Cycle {cycle} ---")

        monitor_proc = ensure_monitor(monitor_proc)

        # ── Discovery ─────────────────────────────────────────
        if cycle == 1 or cycle % DISCOVERY_INTERVAL == 0:
            known_devices = discover_devices()
            # FIX B: sync iptables rules to current IPs after discovery
            sync_rate_limit_rules(dh, known_devices)
        else:
            log(f"Using cached device list ({len(known_devices)} devices)")

        # ── Device join / leave detection ──────────────────────
        curr_iot_set = {ip for ip in known_devices if ip.startswith(IOT_NET)}
        joined = curr_iot_set - prev_iot_set
        left   = prev_iot_set - curr_iot_set

        # Skip join alerts on cycle 1 — all devices appear "new" at startup
        # Also skip JOIN alert if device was previously quarantined (it's a restore, not new join)
        # Also batch alerts: if 3+ devices join simultaneously, send one summary
        if joined and cycle > 1:
            # Filter out devices that were in quarantine (restores handled by restore_alert)
            true_joins = {ip for ip in joined
                          if not any(info.get("last_ip") == ip and info.get("quarantined_before")
                                     for info in dh.values())}
            joined = true_joins
        if joined and cycle > 1:
            if len(joined) >= 3:
                # Batch alert for simultaneous joins (e.g. docker compose up)
                names = []
                for ip in sorted(joined):
                    cname = get_container_name(ip)
                    if not cname or cname == ip: cname = ip
                    names.append(f"{cname} ({ip})")
                log(f"BATCH JOIN: {len(joined)} devices joined network", "ALERT")
                am.send_alert("DEVICE_JOINED", {
                    "device": f"{len(joined)} devices",
                    "ip":     ", ".join(sorted(joined)),
                    "names":  names,
                    "batch":  True,
                })
            else:
                for ip in joined:
                    cname = get_container_name(ip)
                    if not cname or cname == ip:
                        cname = ip
                    log(f"NEW DEVICE JOINED: {cname} ({ip})", "ALERT")
                    am.send_alert("DEVICE_JOINED", {
                        "device": cname,
                        "ip":     ip,
                        "batch":  False,
                    })

        for ip in left:
            cname = next((n for n, info in dh.items()
                          if info.get("last_ip") == ip), ip)
            # Do NOT fire LEFT alert if device was quarantined —
            # it moved to quarantine-lan, it didn't truly leave
            if dh.get(cname, {}).get("quarantined", False):
                log(f"Device {cname} left IoT LAN → quarantined, no LEFT alert")
                continue
            # Also skip if it was just moved to quarantine this cycle
            # (ew_containers or score-based quarantine sets quarantined=True before we get here)
            log(f"DEVICE LEFT NETWORK: {cname} ({ip})", "WARN")
            am.send_alert("DEVICE_LEFT", {
                "device": cname,
                "ip":     ip,
            })
            # Mark as inactive in history
            if cname in dh:
                dh[cname]["active"] = False
                dh[cname]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Update active flag for all currently seen devices
        for ip in curr_iot_set:
            cname = get_container_name(ip)
            if cname and cname != ip and cname in dh:
                dh[cname]["active"] = True
                dh[cname]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        prev_iot_set = curr_iot_set

        # ── FIX A: build ip→container map once per cycle ──────
        # Used in rate-limit loop; avoids docker inspect subprocess calls
        # that silently fail and cause violations to be skipped.
        ip_to_container = build_ip_map(dh)

        # ── Read events from background monitor ───────────────
        scan_events, east_west_events = read_and_clear()
        scan_map      = merge_scan_events(scan_events)
        east_west_map = merge_east_west_events(east_west_events)

        log(f"Monitor events: {len(scan_events)} scan, "
            f"{len(east_west_events)} east-west")

        # Controller's own tcpdump — connection_map + east_west + NEW conn counts
        connection_map, _, new_conn_counts = capture_both(MONITOR_INTERVAL)
        if new_conn_counts:
            log(f"New connection counts this cycle: {dict(new_conn_counts)}")

        # ── Process scan events ───────────────────────────────
        attacked_devices = set()
        _attack_quarantine_pending = {}   # attacker_ip → list of quarantined devices
        for attacker_ip, targets in scan_map.items():
            count = len(targets)
            log(f"SCANNING DETECTED: {attacker_ip} contacted "
                f"{count} IoT devices", "ALERT")
            if attacker_ip.startswith(TRUSTED_NET):
                log(f"EXTERNAL ATTACKER: {attacker_ip} scanning IoT network!", "ALERT")
                # Log only — combined Telegram sent after quarantines are known
                am._write_log(
                    f"EXTERNAL_ATTACKER | Attacker: {attacker_ip} | "
                    f"Targets: {count} IoT devices | Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                _attack_quarantine_pending[attacker_ip] = {"targets": count, "devices": []}
            for dst_ip in targets:
                if dst_ip.startswith(IOT_NET):
                    attacked_devices.add(dst_ip)

        # ── Process east-west events ──────────────────────────
        ew_containers = set()

        for ew_src, ew_dsts in east_west_map.items():
            # Filter out gateway .1 — normal routing, not lateral movement
            ew_dsts = {d for d in ew_dsts if not d.endswith('.1')}
            if not ew_dsts:
                continue
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
                ew_containers.add(ew_container)

                if not dh[ew_container].get("quarantined", False):
                    quarantine_device(
                        ew_container, ew_src,
                        f"East-west lateral movement to {', '.join(ew_dsts)}",
                        dh[ew_container].get("device_type", "Unknown IoT Device"),
                        dh, ew_container
                    )
                    force_rediscovery = True   # pick up new quarantine-lan IP

        # ── Rate limit evaluation ─────────────────────────────
        drop_counts = rl.read_drop_counts()
        log(f"Rate drop counts this cycle: {drop_counts}")  # visible in controller log

        for d_ip, d_drops in new_conn_counts.items():
            # FIX A: use pre-built map instead of docker inspect subprocess
            d_container = ip_to_container.get(d_ip)
            if not d_container:
                # Fallback to docker inspect for IPs not yet in history
                d_container = get_container_name(d_ip)
                if not d_container or d_container == d_ip:
                    log(f"Rate: no container found for {d_ip}, skipping", "WARN")
                    continue

            d_key  = d_container
            d_type = dh.get(d_key, {}).get("device_type", "Unknown IoT Device")

            zone, penalty, recovered, msg = rl.evaluate(
                d_container, d_ip, d_type, d_drops
            )

            dh.setdefault(d_key, {})["rl_penalty"] = penalty

            if zone == "SOFT":
                log(f"RATE BUFFER   | {d_container:15} | {msg}", "WARN")
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": d_ip,
                    "zone": "BUFFER", "penalty": penalty, "message": msg
                })

            elif zone == "HARD":
                log(f"RATE EXCEEDED | {d_container:15} | {msg}", "ALERT")
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": d_ip,
                    "zone": "EXCEEDED", "penalty": penalty, "message": msg
                })
                # FIX C: quarantine immediately on HARD violation —
                # penalty=-35 drops score to 25 (below threshold=40),
                # but don't wait for the scoring loop: quarantine now.
                if not dh.get(d_key, {}).get("quarantined", False):
                    quarantine_device(
                        d_container, d_ip,
                        f"Rate HARD violation — {msg}",
                        d_type,
                        dh, d_key
                    )
                    force_rediscovery = True   # pick up new quarantine-lan IP

            if recovered:
                log(f"RATE RECOVERED| {d_container:15} | penalty cleared")
                dh[d_key]["rl_penalty"] = 0
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": d_ip,
                    "zone": "RECOVERED",
                    "message": "Rate returned to normal — penalty removed"
                })


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
                dh[key]["last_ip"]     = ip
                dh[key]["mac"]         = info["mac"]
                dh[key]["quarantined"] = ip.startswith(QUARANTINE_NET)

                if ip.startswith(IOT_NET) and not dh[key].get("rl_applied", False):
                    log(f"Re-applying rate limit: {container} ({ip})")
                    rl.apply_conn_limit(
                        container, ip,
                        dh[key].get("device_type", "Unknown IoT Device")
                    )
                    dh[key]["rl_applied"] = True
                    if not dh[key].get("restore_alert_sent", False):
                        am.send_alert(am.ALERT_RESTORED, {
                            "device": container,
                            "ip":     ip,
                            "reason": "Manually restored to IoT LAN"
                        })
                        dh[key]["restore_alert_sent"] = True
                        _tmp = json.load(open(DEVICE_HISTORY))
                        _tmp[key]["restore_alert_sent"] = True
                        json.dump(_tmp, open(DEVICE_HISTORY, "w"), indent=2)

            # ── Behavioral flags ──────────────────────────────
            unique_dests = len(connection_map.get(ip, set()))
            dh[key]["connections"]  = unique_dests
            dh[key]["under_attack"] = (ip in attacked_devices)

            if ip in east_west_map:
                dh[key]["east_west"] = True
            elif key not in ew_containers and not dh[key].get("quarantined", False):
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
            persist_score(dh[key], score, reasons)
            status   = get_status(score, dh[key].get("quarantined", False))
            zone_tag = "QUAR" if ip.startswith(QUARANTINE_NET) else "IoT "
            dt_short = dh[key].get("device_type", "Unknown")[:18]

            log(f"{container:15} | {ip:15} | [{zone_tag}] "
                f"{dt_short:18} | Score: {score:3} | {status}")

            # ── Auto quarantine on low score ──────────────────
            if score < SCORE_THRESHOLD:
                if not dh[key].get("quarantined", False):
                    reason_str = f"Trust score {score} | {'; '.join(reasons)}"
                    quarantine_device(
                        container, ip, reason_str,
                        dh[key].get("device_type", "Unknown IoT Device"),
                        dh, key
                    )
                    force_rediscovery = True
                    # Track for combined attack summary message
                    for atk_ip in _attack_quarantine_pending:
                        _attack_quarantine_pending[atk_ip]["devices"].append({
                            "device": container, "ip": ip, "reason": reason_str
                        })

        # ── End of cycle ──────────────────────────────────────
        # ── Track trusted (c-devices) in history ─────────────────
        for _tip, _tinfo in known_devices.items():
            if not _tip.startswith(TRUSTED_NET):
                continue
            _tkey = f"trusted_{_tip.replace('.','_')}"
            _tnow = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if _tkey not in dh:
                dh[_tkey] = {
                    "container"    : _tkey,
                    "last_ip"      : _tip,
                    "mac"          : _tinfo.get("mac", "unknown"),
                    "vendor"       : _tinfo.get("vendor", "Unknown"),
                    "device_type"  : "Trusted Client",
                    "open_ports"   : [],
                    "lan"          : "c-devices",
                    "trust_score"  : 100,
                    "score_reasons": [],
                    "quarantined"  : False,
                    "active"       : True,
                    "last_seen"    : _tnow,
                }
                log(f"Trusted device added to history: {_tip}")
            else:
                dh[_tkey]["last_ip"]   = _tip
                dh[_tkey]["active"]    = True
                dh[_tkey]["last_seen"] = _tnow

        # ── Track trusted (c-devices) in history ─────────────────
        for _tip, _tinfo in known_devices.items():
            if not _tip.startswith(TRUSTED_NET):
                continue
            _tkey = f"trusted_{_tip.replace('.','_')}"
            _tnow = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if _tkey not in dh:
                dh[_tkey] = {
                    "container"    : _tkey,
                    "last_ip"      : _tip,
                    "mac"          : _tinfo.get("mac", "unknown"),
                    "vendor"       : _tinfo.get("vendor", "Unknown"),
                    "device_type"  : "Trusted Client",
                    "open_ports"   : [],
                    "lan"          : "c-devices",
                    "trust_score"  : 100,
                    "score_reasons": [],
                    "quarantined"  : False,
                    "active"       : True,
                    "last_seen"    : _tnow,
                }
                log(f"Trusted device added to history: {_tip}")
            else:
                dh[_tkey]["last_ip"]   = _tip
                dh[_tkey]["active"]    = True
                dh[_tkey]["last_seen"] = _tnow

        try:
            with open(HEARTBEAT_FILE, "w") as _hb:
                _hb.write(datetime.now().isoformat())
        except Exception:
            pass

        rl.reset_counters()
        # ── Send combined attack+quarantine Telegram summary ─────
        for atk_ip, info in _attack_quarantine_pending.items():
            # Write alert log entry for dashboard (always)
            am.send_alert(am.ALERT_ATTACKER, {
                "attacker": atk_ip,
                "targets" : info["targets"],
            })
            # Send combined Telegram only if there were resulting quarantines
            if info["devices"]:
                am.send_attack_summary(atk_ip, info["targets"], info["devices"])

        save_history(dh)
        log(f"Cycle {cycle} complete. {len(known_devices)} devices. History saved.")
        log(f"Sleeping {SLEEP_BETWEEN}s...")
        time.sleep(SLEEP_BETWEEN)


if __name__ == "__main__":
    main()

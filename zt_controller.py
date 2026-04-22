#!/usr/bin/env python3
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

IOT_NET            = env("IOT_NET",            "192.168.20")
TRUSTED_NET        = env("TRUSTED_NET",        "192.168.10")
QUARANTINE_NET     = env("QUARANTINE_NET",     "192.168.30")
SCAN_THRESHOLD     = int(env("SCAN_THRESHOLD",     "3"))
MONITOR_INTERVAL   = int(env("MONITOR_INTERVAL",   "2"))
DISCOVERY_INTERVAL = int(env("DISCOVERY_INTERVAL", "3"))
SLEEP_BETWEEN      = int(env("SLEEP_BETWEEN",      "1"))
BEHAVIOR_MONITOR   = env("BEHAVIOR_MONITOR", "/home/sk/behavior_monitor.sh")
DEVICE_HISTORY     = env("DEVICE_HISTORY",   "/home/sk/device_history.json")


def start_monitor():
    log("Starting background behavioral monitor...")
    try:
        proc = subprocess.Popen(
            ["sudo", "bash", BEHAVIOR_MONITOR],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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
    """Reverse { ip: container_name } map from device_history — O(1) lookup."""
    return {info["last_ip"]: name for name, info in dh.items() if info.get("last_ip")}


def sync_rate_limit_rules(dh, known_devices):
    """Re-sync iptables rules when container IPs change after restart."""
    iot_prefix = IOT_NET + "."
    for ip, info in known_devices.items():
        if not ip.startswith(iot_prefix):
            continue
        container = get_container_name(ip)
        if not container or container == ip or container not in dh:
            continue
        old_ip = dh[container].get("last_ip", "")
        if old_ip and old_ip != ip and not dh[container].get("quarantined", False):
            dev_type = dh[container].get("device_type", "Unknown IoT Device")
            log(f"IP changed: {container} {old_ip} → {ip}, re-syncing iptables rule")
            rl.remove_limit(container, old_ip, dev_type)
            rl.apply_hard_limit(container, ip, dev_type)
            dh[container]["last_ip"]    = ip
            dh[container]["rl_applied"] = True


def main():
    log("=" * 60)
    log("Zero Trust IoT Gateway Controller Started")
    log("=" * 60)

    dh               = load_history()
    known_devices    = {}
    cycle            = 0
    force_rediscovery = False
    prev_iot_set  = set()
    prev_quar_set = set()

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

        if cycle == 1 or cycle % DISCOVERY_INTERVAL == 0:
            known_devices = discover_devices()
            sync_rate_limit_rules(dh, known_devices)
        else:
            log(f"Using cached device list ({len(known_devices)} devices)")

        curr_iot_set = {ip for ip in known_devices if ip.startswith(IOT_NET)}
        joined = curr_iot_set - prev_iot_set
        left   = prev_iot_set - curr_iot_set

        if joined and cycle > 1:
            def _is_restored(ip):
                cname = get_container_name(ip)
                if not cname or cname == ip:
                    return False
                info = dh.get(cname, {})
                return info.get("just_restored", False) or info.get("quarantined_before", False)
            joined = {ip for ip in joined if not _is_restored(ip)}
            # Clear just_restored flags after use
            for info in dh.values():
                if info.get("just_restored"):
                    info["just_restored"] = False
        if joined and cycle > 1:
            if len(joined) >= 3:
                names = []
                for ip in sorted(joined):
                    cname = get_container_name(ip)
                    if not cname or cname == ip: cname = ip
                    names.append(f"{cname} ({ip})")
                log(f"BATCH JOIN: {len(joined)} devices joined network", "ALERT")
                am.send_alert("DEVICE_JOINED", {
                    "device": f"{len(joined)} devices",
                    "ip":     ", ".join(sorted(joined)),
                    "names":  names, "batch": True,
                })
            else:
                for ip in joined:
                    cname = get_container_name(ip)
                    if not cname or cname == ip: cname = ip
                    log(f"NEW DEVICE JOINED: {cname} ({ip})", "ALERT")
                    am.send_alert("DEVICE_JOINED", {"device": cname, "ip": ip, "batch": False})

        for ip in left:
            cname = next((n for n, info in dh.items() if info.get("last_ip") == ip), ip)
            if dh.get(cname, {}).get("quarantined", False):
                log(f"Device {cname} left IoT LAN → already quarantined, no LEFT alert")
                continue
            # Skip if device now on quarantine-lan (dashboard quarantine between cycles)
            on_quar = next((qip for qip in known_devices
                            if qip.startswith(QUARANTINE_NET)
                            and get_container_name(qip) == cname), None)
            if on_quar:
                log(f"Device {cname} found on quarantine-lan ({on_quar}), no LEFT alert")
                if cname in dh:
                    dh[cname]["quarantined"] = True
                    dh[cname]["active"]      = True
                continue
            log(f"DEVICE LEFT NETWORK: {cname} ({ip})", "WARN")
            am.send_alert("DEVICE_LEFT", {"device": cname, "ip": ip})
            if cname in dh:
                dh[cname]["active"]    = False
                dh[cname]["last_seen"] = now_str
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for ip in curr_iot_set:
            cname = get_container_name(ip)
            if cname and cname != ip and cname in dh:
                dh[cname]["active"]    = True
                dh[cname]["last_seen"] = now_str
        # Quarantine-lan devices are still running — keep active=True
        for ip in known_devices:
            if not ip.startswith(QUARANTINE_NET):
                continue
            cname = get_container_name(ip)
            if cname and cname != ip and cname in dh:
                dh[cname]["active"]      = True
                dh[cname]["quarantined"] = True
                dh[cname]["last_seen"]   = now_str

        prev_iot_set  = curr_iot_set

        # ── Quarantine-LAN join / leave detection ────────────
        curr_quar_set = {ip for ip in known_devices if ip.startswith(QUARANTINE_NET)}
        quar_joined   = curr_quar_set - prev_quar_set
        quar_left     = prev_quar_set - curr_quar_set

        for ip in quar_joined:
            cname = get_container_name(ip)
            if not cname or cname == ip: cname = ip
            # Alert for any new IP on quarantine-lan UNLESS we put it there this cycle
            # (quarantine_device() sets quarantined=True AND rl_applied=False in same cycle)
            # A device moved by us will already be in dh with quarantined=True from BEFORE this cycle
            # A device that appeared independently will either not be in dh, or have quarantined=False
            was_moved_by_us = (
                dh.get(cname, {}).get("quarantined", False) and
                dh.get(cname, {}).get("quarantine_count", 0) > 0
            )
            if not was_moved_by_us:
                log(f"NEW DEVICE ON QUARANTINE LAN: {cname} ({ip})", "ALERT")
                am.send_alert("DEVICE_JOINED", {
                    "device": cname, "ip": ip, "batch": False,
                })

        for ip in quar_left:
            # Use get_container_name first (resolves by inspecting networks)
            # Fall back to dh lookup by last_ip
            cname = get_container_name(ip)
            if not cname or cname == ip:
                cname = next((n for n, info in dh.items() if info.get("last_ip") == ip), ip)
            log(f"DEVICE LEFT QUARANTINE LAN: {cname} ({ip})", "WARN")
            am.send_alert("DEVICE_LEFT", {"device": cname, "ip": ip})
            if cname in dh:
                dh[cname]["active"]    = False
                dh[cname]["last_seen"] = now_str

        prev_quar_set = curr_quar_set
        ip_to_container = build_ip_map(dh)

        scan_events, east_west_events = read_and_clear()
        scan_map      = merge_scan_events(scan_events)
        east_west_map = merge_east_west_events(east_west_events)
        log(f"Monitor events: {len(scan_events)} scan, {len(east_west_events)} east-west")

        connection_map, _, new_conn_counts = capture_both(MONITOR_INTERVAL)
        if new_conn_counts:
            log(f"New connection counts this cycle: {dict(new_conn_counts)}")

        attacked_devices           = set()
        _attack_quarantine_pending = {}
        for attacker_ip, targets in scan_map.items():
            count = len(targets)
            log(f"SCANNING DETECTED: {attacker_ip} contacted {count} IoT devices", "ALERT")
            if attacker_ip.startswith(TRUSTED_NET):
                log(f"EXTERNAL ATTACKER: {attacker_ip} scanning IoT network!", "ALERT")
                _attack_quarantine_pending[attacker_ip] = {"targets": count, "devices": []}
            for dst_ip in targets:
                if dst_ip.startswith(IOT_NET):
                    attacked_devices.add(dst_ip)

        # Load whitelist for east-west check
        _wl = []
        try:
            with open(env("WHITELIST_FILE", "/home/sk/iot_whitelist.json")) as _wf:
                _wl = json.load(_wf)
        except Exception:
            pass

        ew_containers = set()

        # Load whitelist once per cycle for east-west filtering
        _wl_rules = []
        try:
            import json as _jwl
            with open(os.path.join(os.environ.get("SK_HOME", "/home/sk"), "iot_whitelist.json")) as _wf:
                _wl_rules = _jwl.load(_wf)
        except Exception as _wl_err:
            log(f"Whitelist load error: {_wl_err}", "WARN")

        for ew_src, ew_dsts in east_west_map.items():
            ew_dsts = {d for d in ew_dsts if not d.endswith('.1')}
            if not ew_dsts:
                continue
            ew_container = get_container_name(ew_src)
            if not ew_container or ew_container == ew_src:
                log(f"EW: cannot resolve container for {ew_src}, skipping", "WARN")
                continue

            # Check each destination against whitelist
            blocked_dsts = set()
            allowed_dsts = set()
            for dst_ip in ew_dsts:
                dst_name = get_container_name(dst_ip)
                if dst_name and dst_name != dst_ip:
                    is_wl = any(
                        r.get("src") == ew_container and r.get("dst") == dst_name
                        for r in _wl_rules
                    )
                    if is_wl:
                        allowed_dsts.add(dst_ip)
                        log(f"WHITELIST ALLOW: {ew_container} ({ew_src}) → {dst_name} ({dst_ip})")
                    else:
                        blocked_dsts.add(dst_ip)
                else:
                    # Cannot resolve dst — treat as blocked
                    blocked_dsts.add(dst_ip)
                    log(f"EW: cannot resolve {dst_ip}, treating as blocked", "WARN")

            if not blocked_dsts:
                log(f"EW: {ew_container} all {len(allowed_dsts)} destination(s) whitelisted — no action")
                continue

            # Only act on non-whitelisted destinations
            log(f"EAST-WEST DETECTED: {ew_container} ({ew_src}) → {len(blocked_dsts)} blocked IoT device(s)", "ALERT")
            am.send_alert(am.ALERT_EAST_WEST, {
                "src_device": ew_container, "src_ip": ew_src,
                "dst_ip":     ", ".join(blocked_dsts), "attempts": len(blocked_dsts),
            })
            if ew_container in dh:
                dh[ew_container]["east_west"] = True
                ew_containers.add(ew_container)
                if not dh[ew_container].get("quarantined", False):
                    _ew_reason = f"East-west lateral movement to {', '.join(blocked_dsts)}"
                    dh[ew_container]["quarantine_reason"] = _ew_reason
                    quarantine_device(
                        ew_container, ew_src, _ew_reason,
                        dh[ew_container].get("device_type", "Unknown IoT Device"),
                        dh, ew_container
                    )
                    force_rediscovery = True
        drop_counts = rl.read_drop_counts()
        log(f"Rate drop counts this cycle: {drop_counts}")

        for d_ip, d_drops in new_conn_counts.items():
            d_container = ip_to_container.get(d_ip) or get_container_name(d_ip)
            if not d_container or d_container == d_ip:
                log(f"Rate: no container found for {d_ip}, skipping", "WARN")
                continue

            d_key  = d_container
            d_type = dh.get(d_key, {}).get("device_type", "Unknown IoT Device")
            zone, penalty, recovered, msg = rl.evaluate(d_container, d_ip, d_type, d_drops)
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
                if not dh.get(d_key, {}).get("quarantined", False):
                    _rate_reason = f"Rate HARD violation — {msg}"
                    dh.get(d_key, {})["quarantine_reason"] = _rate_reason
                    quarantine_device(d_container, d_ip, _rate_reason,
                                      d_type, dh, d_key)
                    force_rediscovery = True

            if recovered:
                log(f"RATE RECOVERED| {d_container:15} | penalty cleared")
                dh[d_key]["rl_penalty"] = 0
                am.send_alert(am.ALERT_SCORE_DROP, {
                    "device": d_container, "ip": d_ip, "zone": "RECOVERED",
                    "message": "Rate returned to normal — penalty removed"
                })

        for ip, info in known_devices.items():
            container = get_container_name(ip)
            if not container or container == ip:
                continue
            key = container

            if key not in dh:
                ports, dev_type = fingerprint_device(ip)
                log(f"Fingerprinted: {container} ({ip}) → {ports} → {dev_type}")
                if ip.startswith(IOT_NET):
                    rl.apply_conn_limit(container, ip, dev_type)
                dh[key] = {
                    "container": container, "last_ip": ip,
                    "mac": info["mac"], "vendor": info["vendor"],
                    "device_type": dev_type, "open_ports": ports,
                    "scanning": False, "connections": 0,
                    "under_attack": False, "east_west": False,
                    "quarantined_before": False, "quarantined": False,
                    "quarantine_count": 0, "rl_penalty": 0,
                    "rl_applied": ip.startswith(IOT_NET),
                    "date_joined": now_str,
                    "quarantine_reason": "",
                }
            else:
                dh[key]["last_ip"]     = ip
                dh[key]["mac"]         = info["mac"]
                dh[key]["quarantined"] = ip.startswith(QUARANTINE_NET)

                if ip.startswith(IOT_NET) and not dh[key].get("rl_applied", False):
                    log(f"Re-applying rate limit: {container} ({ip})")
                    rl.apply_conn_limit(container, ip, dh[key].get("device_type", "Unknown IoT Device"))
                    dh[key]["rl_applied"] = True
                    if not dh[key].get("restore_alert_sent", False):
                        am.send_alert(am.ALERT_RESTORED, {"device": container, "ip": ip,
                                                           "reason": "Manually restored to IoT LAN"})
                        dh[key]["restore_alert_sent"] = True
                        dh[key]["just_restored"]      = True
                        _tmp = json.load(open(DEVICE_HISTORY))
                        _tmp[key]["restore_alert_sent"] = True
                        json.dump(_tmp, open(DEVICE_HISTORY, "w"), indent=2)

            unique_dests        = len(connection_map.get(ip, set()))
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
                log(f"TARGET: {container} ({ip}) [{dh[key]['device_type']}] being scanned", "WARN")

            if not dh[key].get("quarantined", False):
                exceeded, conn_count, conn_limit, conn_msg = rl.check_active_connections(
                    container, ip, dh[key].get("device_type", "Unknown IoT Device"))
                if exceeded:
                    log(f"ACTIVE CONN EXCEEDED: {container} ({ip}) — {conn_count}/{conn_limit}", "ALERT")
                    am.send_alert(am.ALERT_QUARANTINE, {"device": container, "ip": ip, "reason": conn_msg})
                    dh[key]["quarantine_reason"] = conn_msg
                    quarantine_device(container, ip, conn_msg,
                                      dh[key].get("device_type", "Unknown IoT Device"), dh, key)
                    continue

            score, reasons = calculate_trust_score(dh[key])
            persist_score(dh[key], score, reasons)
            status   = get_status(score, dh[key].get("quarantined", False))
            zone_tag = "QUAR" if ip.startswith(QUARANTINE_NET) else "IoT "
            log(f"{container:15} | {ip:15} | [{zone_tag}] "
                f"{dh[key].get('device_type','Unknown')[:18]:18} | Score: {score:3} | {status}")

            if score < SCORE_THRESHOLD and not dh[key].get("quarantined", False):
                reason_str = f"Trust score {score} | {'; '.join(reasons)}"
                quarantine_device(container, ip, reason_str,
                                  dh[key].get("device_type", "Unknown IoT Device"), dh, key)
                force_rediscovery = True
                for atk_ip in _attack_quarantine_pending:
                    _attack_quarantine_pending[atk_ip]["devices"].append(
                        {"device": container, "ip": ip, "reason": reason_str})

        # Track trusted (c-devices)
        for _tip, _tinfo in known_devices.items():
            if not _tip.startswith(TRUSTED_NET):
                continue
            _tkey = f"trusted_{_tip.replace('.','_')}"
            if _tkey not in dh:
                dh[_tkey] = {
                    "container": _tkey, "last_ip": _tip,
                    "mac": _tinfo.get("mac", "unknown"), "vendor": _tinfo.get("vendor", "Unknown"),
                    "device_type": "Trusted Client", "open_ports": [], "lan": "c-devices",
                    "trust_score": 100, "score_reasons": [], "quarantined": False,
                    "active": True, "last_seen": now_str,
                }
                log(f"Trusted device added to history: {_tip}")
            else:
                dh[_tkey]["last_ip"]   = _tip
                dh[_tkey]["active"]    = True
                dh[_tkey]["last_seen"] = now_str

        try:
            with open(HEARTBEAT_FILE, "w") as _hb:
                _hb.write(datetime.now().isoformat())
        except Exception:
            pass

        rl.reset_counters()

        for atk_ip, info in _attack_quarantine_pending.items():
            am.send_alert(am.ALERT_ATTACKER, {"attacker": atk_ip, "targets": info["targets"]})
            if info["devices"]:
                am.send_attack_summary(atk_ip, info["targets"], info["devices"])

        save_history(dh)
        log(f"Cycle {cycle} complete. {len(known_devices)} devices. History saved.")
        log(f"Sleeping {SLEEP_BETWEEN}s...")
        time.sleep(SLEEP_BETWEEN)


if __name__ == "__main__":
    main()

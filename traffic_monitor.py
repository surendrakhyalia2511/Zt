#!/usr/bin/env python3
"""
traffic_monitor.py
Zero Trust IoT Gateway — Traffic and East-West Monitoring

Runs two tcpdump captures in parallel every cycle:
  1. ens37    — C-Devices LAN → IoT LAN (detects external attacker scans)
  2. docker-iot bridge — IoT → IoT (detects east-west lateral movement)

Both run simultaneously for MONITOR_INTERVAL seconds so no time is wasted.
"""

import subprocess
import threading
from collections import defaultdict
from logger import log

IOT_NET     = "192.168.20"
TRUSTED_NET = "192.168.10"
BRIDGE_IOT  = "docker-iot"


def capture_both(duration):
    """
    Run ens37 and docker-iot tcpdump captures in parallel.

    Args:
        duration : int — seconds to capture

    Returns:
        connection_map : { src_ip: set(dst_ips) }
                         Kali/trusted → IoT LAN connections (attack scan)
        east_west_map  : { src_ip: set(dst_ips) }
                         IoT → IoT connections (lateral movement)
    """
    log(f"Monitoring traffic on ens37 + docker-iot for {duration} seconds...")

    ens37_out  = [None]
    bridge_out = [None]

    def _capture_ens37():
        ens37_out[0] = subprocess.run(
            ["timeout", str(duration), "tcpdump",
             "-i", "ens37", "-nn", "-q",
             f"src net {TRUSTED_NET}.0/24 and dst net {IOT_NET}.0/24"],
            capture_output=True, text=True
        )

    def _capture_bridge():
        bridge_out[0] = subprocess.run(
            ["timeout", str(duration), "tcpdump",
             "-i", BRIDGE_IOT, "-nn", "-q", "-c", "500",
             f"src net {IOT_NET}.0/24 and dst net {IOT_NET}.0/24"],
            capture_output=True, text=True
        )

    t1 = threading.Thread(target=_capture_ens37)
    t2 = threading.Thread(target=_capture_bridge)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # ── Parse ens37 → connection_map ──────────────────────────
    connection_map = defaultdict(set)
    if ens37_out[0]:
        for line in ens37_out[0].stdout.splitlines():
            if "IP" not in line:
                continue
            parts = line.split()
            for i, token in enumerate(parts):
                if token == "IP" and i + 3 < len(parts):
                    src_ip = ".".join(parts[i+1].split(".")[:4])
                    dst_ip = ".".join(parts[i+3].rstrip(":").split(".")[:4])
                    if src_ip.startswith(TRUSTED_NET):
                        connection_map[src_ip].add(dst_ip)
                    break

    # ── Parse bridge → east_west_map ──────────────────────────
    east_west_map = defaultdict(set)
    if bridge_out[0]:
        for line in bridge_out[0].stdout.splitlines():
            if "IP" not in line:
                continue
            parts = line.split()
            for i, token in enumerate(parts):
                if token == "IP" and i + 3 < len(parts):
                    src_ip = ".".join(parts[i+1].split(".")[:4])
                    dst_ip = ".".join(parts[i+3].rstrip(":").split(".")[:4])
                    if (src_ip.startswith(IOT_NET) and
                            dst_ip.startswith(IOT_NET) and
                            src_ip != dst_ip):
                        east_west_map[src_ip].add(dst_ip)
                    break

    return connection_map, east_west_map


def detect_scan(connection_map, trusted_net, iot_net, scan_threshold):
    """
    Analyse connection_map for scanning behavior.

    Args:
        connection_map  : output from capture_both()
        trusted_net     : TRUSTED_NET prefix string
        iot_net         : IOT_NET prefix string
        scan_threshold  : min unique destinations to count as scan

    Returns:
        attacked_devices : set of IoT IPs being actively targeted
        attacker_ips     : set of attacker source IPs detected
    """
    attacked_devices = set()
    attacker_ips     = set()

    for src_ip, dsts in connection_map.items():
        count = len(dsts)
        if count >= scan_threshold:
            log(f"SCANNING DETECTED: {src_ip} contacted {count} IoT devices", "ALERT")
            if src_ip.startswith(trusted_net):
                log(f"EXTERNAL ATTACKER: {src_ip} scanning IoT network!", "ALERT")
                attacker_ips.add(src_ip)
                for dst_ip in dsts:
                    if dst_ip.startswith(iot_net):
                        attacked_devices.add(dst_ip)

    return attacked_devices, attacker_ips

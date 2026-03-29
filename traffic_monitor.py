#!/usr/bin/env python3
"""
traffic_monitor.py
Zero Trust IoT Gateway — Traffic and East-West Monitoring

NEW: count_new_connections() counts SYN packets per source IP
     from tcpdump output — zero iptables dependency, always works.
"""

import subprocess
import threading
from collections import defaultdict
from logger import log
import sys, os
sys.path.insert(0, os.environ.get("APP_PATH", "/home/sk"))
from env_loader import env

IOT_NET     = env("IOT_NET",     "192.168.20")
TRUSTED_NET = env("TRUSTED_NET", "192.168.10")
BRIDGE_IOT  = env("BRIDGE_IOT",  "docker-iot")
TRUSTED_IF  = env("TRUSTED_IFACE", "ens37")


def capture_both(duration):
    """
    Run ens37 and docker-iot tcpdump captures in parallel.
    Returns:
        connection_map : { src_ip: set(dst_ips) }  — trusted→IoT (scan detection)
        east_west_map  : { src_ip: set(dst_ips) }  — IoT→IoT (lateral movement)
        new_conn_counts: { src_ip: int }            — NEW connections per IoT device
    """
    log(f"Monitoring traffic on {TRUSTED_IF} + docker-iot for {duration} seconds...")

    ens37_lines  = [None]
    bridge_lines = [None]
    iot_out      = [None]

    def _capture_ens37():
        r = subprocess.run(
            ["timeout", str(duration), "tcpdump",
             "-i", TRUSTED_IF, "-nn", "-q",
             f"src net {TRUSTED_NET}.0/24 and dst net {IOT_NET}.0/24"],
            capture_output=True, text=True
        )
        ens37_lines[0] = r.stdout

    def _capture_bridge():
        r = subprocess.run(
            ["timeout", str(duration), "tcpdump",
             "-i", BRIDGE_IOT, "-nn", "-q", "-c", "500",
             f"src net {IOT_NET}.0/24 and dst net {IOT_NET}.0/24"],
            capture_output=True, text=True
        )
        bridge_lines[0] = r.stdout

    def _capture_iot_syn():
        """
        Capture NEW TCP connections from IoT devices to outside.
        'tcp[tcpflags] & tcp-syn != 0' matches SYN packets only.
        Each SYN = one new connection attempt.
        """
        r = subprocess.run(
            ["timeout", str(duration), "tcpdump",
             "-i", BRIDGE_IOT, "-nn", "-q", "-c", "2000",
             f"src net {IOT_NET}.0/24 and "
             f"not dst net {IOT_NET}.0/24 and "
             f"tcp[tcpflags] & tcp-syn != 0"],
            capture_output=True, text=True
        )
        iot_out[0] = r.stdout

    t1 = threading.Thread(target=_capture_ens37)
    t2 = threading.Thread(target=_capture_bridge)
    t3 = threading.Thread(target=_capture_iot_syn)
    t1.start(); t2.start(); t3.start()
    t1.join();  t2.join();  t3.join()

    # ── Parse ens37 → connection_map ──────────────────────────
    connection_map = defaultdict(set)
    for line in (ens37_lines[0] or "").splitlines():
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

    # ── Parse docker-iot bridge → east_west_map ───────────────
    east_west_map = defaultdict(set)
    for line in (bridge_lines[0] or "").splitlines():
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

    # ── Parse IoT SYN packets → new_conn_counts ───────────────
    # Count SYN packets per source IP = new connection attempts
    new_conn_counts = defaultdict(int)
    for line in (iot_out[0] or "").splitlines():
        if "IP" not in line:
            continue
        parts = line.split()
        for i, token in enumerate(parts):
            if token == "IP" and i + 1 < len(parts):
                src_raw = parts[i+1]
                # Remove port (last segment after last dot)
                src_parts = src_raw.split(".")
                if len(src_parts) >= 4:
                    src_ip = ".".join(src_parts[:4])
                    if src_ip.startswith(IOT_NET):
                        new_conn_counts[src_ip] += 1
                break

    return connection_map, east_west_map, new_conn_counts


def detect_scan(connection_map, trusted_net, iot_net, scan_threshold):
    """Analyse connection_map for scanning behavior."""
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

#!/usr/bin/env python3
"""
discovery.py
Zero Trust IoT Gateway — Device Discovery and Fingerprinting
"""

import subprocess
import json
from logger import log

IOT_NET        = "192.168.20"
QUARANTINE_NET = "192.168.30"
BRIDGE_IOT     = "docker-iot"
BRIDGE_QUAR    = "docker-quar"

PORT_TYPE_MAP = {
    80:   "HTTP Device",
    443:  "HTTPS Device",
    1883: "MQTT Sensor/Actuator",
    631:  "Network Printer",
    554:  "IP Camera / NVR",
    8080: "Web Device",
    22:   "SSH Device",
}


def discover_devices():
    """
    ARP scan both IoT LAN and Quarantine LAN.
    Returns: { ip: {mac, vendor, quarantined} }
    """
    log("Running device discovery on IoT + Quarantine networks...")
    devices = {}
    for bridge, net in [(BRIDGE_IOT, IOT_NET), (BRIDGE_QUAR, QUARANTINE_NET)]:
        r = subprocess.run(
            ["arp-scan", f"--interface={bridge}", "--localnet"],
            capture_output=True, text=True
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith(net):
                ip      = parts[0]
                mac     = parts[1]
                vendor  = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                is_quar = (net == QUARANTINE_NET)
                devices[ip] = {"mac": mac, "vendor": vendor, "quarantined": is_quar}
                zone = "QUARANTINE" if is_quar else "IoT LAN"
                log(f"Discovered [{zone}]: {ip} | {mac} | {vendor}")
    return devices


def fingerprint_device(ip):
    """
    nmap port scan → classify device type.
    Returns: (open_ports[], device_type_str)
    """
    try:
        r = subprocess.run(
            ["nmap", "-p", "80,443,1883,631,554,22,8080",
             "--open", "-T4", "--host-timeout", "3s", ip],
            capture_output=True, text=True, timeout=10
        )
        open_ports = []
        for line in r.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                try:
                    open_ports.append(int(line.split("/")[0].strip()))
                except ValueError:
                    pass

        device_type = "Unknown IoT Device"
        for port in [554, 631, 1883, 80, 443, 8080, 22]:
            if port in open_ports:
                device_type = PORT_TYPE_MAP.get(port, "Unknown IoT Device")
                break

        return open_ports, device_type
    except Exception:
        return [], "Unknown IoT Device"


def get_container_name(ip):
    """
    Resolve container name from IP by inspecting iot-lan and quarantine-lan.
    Returns container name or falls back to IP string.
    """
    for network in ["iot-lan", "quarantine-lan"]:
        r = subprocess.run(
            ["docker", "network", "inspect", network],
            capture_output=True, text=True
        )
        try:
            data = json.loads(r.stdout)
            for cid, info in data[0]["Containers"].items():
                if info["IPv4Address"].split("/")[0] == ip:
                    return info["Name"]
        except Exception:
            pass
    return ip

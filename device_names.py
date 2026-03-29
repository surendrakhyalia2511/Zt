#!/usr/bin/env python3
"""
device_names.py
Zero Trust IoT Gateway — Device Name Library

Three-layer identification:
  Layer 1: MAC OUI prefix → manufacturer name
  Layer 2: Open port fingerprint → device category
  Layer 3: Container name heuristics → friendly display name

Usage:
  from device_names import get_friendly_name, get_manufacturer, get_device_icon
"""

# ── OUI → Manufacturer (top IoT vendors) ──────────────────────
# Format: first 6 hex chars (no colons, uppercase) → brand name
OUI_MAP = {
    # Amazon / Ring / Echo
    "F0272D": "Amazon", "AC63BE": "Amazon", "68370E": "Amazon",
    "B47C9C": "Amazon", "A4C138": "Amazon Ring", "18743E": "Amazon Echo",

    # Google / Nest / Chromecast
    "B4F61C": "Google", "3C5AB4": "Google Nest", "6C5AB5": "Google Nest",
    "54600A": "Chromecast", "6C56A1": "Google Home", "F88FCA": "Google",

    # Apple / HomeKit
    "3C22FB": "Apple", "A45E60": "Apple", "ACDE48": "Apple HomeKit",
    "F0DCE2": "Apple", "D89695": "Apple",

    # Philips Hue
    "001788": "Philips Hue", "EC1BBD": "Philips Hue", "001E06": "Philips",

    # Samsung SmartThings
    "CC07AB": "Samsung", "8C771F": "Samsung SmartThings",
    "6C2F2C": "Samsung", "A4EBD3": "Samsung",

    # TP-Link / Kasa / Tapo
    "50C7BF": "TP-Link Kasa", "B0487A": "TP-Link", "E84DDE": "TP-Link Tapo",
    "5C628B": "TP-Link", "14EBB6": "TP-Link",

    # Sonos
    "B8E937": "Sonos", "94DFDD": "Sonos", "48A6B8": "Sonos", "5CAA6D": "Sonos",

    # Wyze
    "2CAA8E": "Wyze", "D0DD49": "Wyze",

    # Eufy / Anker
    "F4909C": "Eufy", "98F1B3": "Anker",

    # Belkin / WeMo
    "B4750E": "Belkin WeMo", "EC1A59": "Belkin", "94103E": "Belkin",

    # ASUS router/IoT
    "F832E4": "ASUS", "AABBCC": "ASUS",

    # Raspberry Pi (lab/dev)
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",

    # Espressif (ESP8266/ESP32 — DIY IoT)
    "24D7EB": "Espressif DIY", "A4CF12": "Espressif DIY", "30AEA4": "Espressif DIY",
    "246F28": "Espressif DIY", "3C71BF": "Espressif DIY",

    # Tuya (generic smart home chip)
    "68C63A": "Tuya Device", "50D4F7": "Tuya Device",

    # Shelly (smart relays)
    "C45BBE": "Shelly", "E868E7": "Shelly",

    # Fibaro
    "000232": "Fibaro",

    # Ubiquiti
    "788A20": "Ubiquiti", "E063DA": "Ubiquiti",

    # Netgear
    "A021B7": "Netgear", "2C3033": "Netgear",

    # Hikvision / Dahua (IP cameras)
    "C0567B": "Hikvision", "303EDB": "Hikvision", "BC327E": "Dahua",

    # Reolink
    "EC3680": "Reolink",

    # Logitech
    "0021B9": "Logitech", "40D855": "Logitech",

    # Roku
    "B09DD9": "Roku", "CC6EB0": "Roku", "DC3A5E": "Roku",

    # LG
    "CC2D8C": "LG", "A8B86E": "LG",

    # Sony
    "001A80": "Sony", "D4BEF9": "Sony",

    # Docker / VM (locally administered — lab only)
    "000000": "Virtual/Docker",
}

# ── Port → Device category ─────────────────────────────────────
PORT_CATEGORY = {
    631:  ("Network Printer",      "🖨️"),
    554:  ("IP Camera / NVR",      "📷"),
    1883: ("MQTT Sensor",          "📡"),
    8883: ("MQTT Sensor (TLS)",    "📡"),
    80:   ("Smart Device",         "📱"),
    443:  ("Smart Device",         "🔐"),
    8080: ("Device Web Interface", "🌐"),
    22:   ("SSH Device",           "💻"),
    23:   ("Telnet Device",        "⚠️"),
    9100: ("Network Printer",      "🖨️"),
    5353: ("mDNS Device",          "📶"),
    8888: ("Camera Stream",        "📷"),
    37777:("Dahua Camera",         "📷"),
    34567:("Hikvision Camera",     "📷"),
    4840: ("OPC-UA Industrial",    "🏭"),
}

# ── Container name → Friendly display name ─────────────────────
CONTAINER_FRIENDLY = {
    # Cameras
    "cam1":       ("Front Door Camera",  "📷"),
    "cam2":       ("Back Door Camera",   "📷"),
    "nvr":        ("Security Recorder",  "🎥"),

    # Access control
    "lock1":      ("Smart Door Lock",    "🔒"),
    "lock2":      ("Garage Lock",        "🔒"),
    "badge":      ("Badge Reader",       "🪪"),

    # Network / Storage
    "nas":        ("Home Storage",       "💾"),
    "router":     ("Home Router",        "📡"),

    # Environmental
    "thermo1":    ("Thermostat",         "🌡️"),
    "thermo2":    ("Bedroom Thermostat", "🌡️"),
    "envsensor":  ("Environment Sensor", "🌿"),
    "sensorhub":  ("Sensor Hub",         "🔗"),

    # Energy
    "energymeter":("Energy Monitor",     "⚡"),
    "plug1":      ("Smart Plug",         "🔌"),
    "plug2":      ("Smart Plug 2",       "🔌"),

    # Lighting
    "bulb1":      ("Smart Bulb",         "💡"),
    "bulb2":      ("Smart Bulb 2",       "💡"),
    "lighting":   ("Lighting Controller","💡"),

    # Entertainment
    "tv1":        ("Smart TV",           "📺"),
    "tv2":        ("Bedroom TV",         "📺"),
    "chromecast": ("Chromecast",         "📺"),
    "appletv":    ("Apple TV",           "📺"),

    # Printing
    "printer":    ("Home Printer",       "🖨️"),

    # Other common names
    "alexa":      ("Amazon Echo",        "🔊"),
    "echo":       ("Amazon Echo",        "🔊"),
    "nest":       ("Google Nest",        "🏠"),
    "hue":        ("Philips Hue Bridge", "💡"),
    "sonos":      ("Sonos Speaker",      "🔊"),
}

# ── Default icons by device type string ───────────────────────
TYPE_ICONS = {
    "Network Printer":      "🖨️",
    "IP Camera / NVR":      "📷",
    "MQTT Sensor/Actuator": "📡",
    "HTTP Device":          "📱",
    "HTTPS Device":         "🔐",
    "Web Device":           "🌐",
    "SSH Device":           "💻",
    "Unknown IoT Device":   "📦",
}


def get_oui(mac: str) -> str:
    """Extract OUI (first 6 hex chars) from MAC address."""
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    return clean[:6] if len(clean) >= 6 else ""


def get_manufacturer(mac: str) -> str:
    """
    Look up manufacturer from MAC OUI.
    Returns manufacturer name or empty string if unknown.
    """
    oui = get_oui(mac)
    if not oui:
        return ""
    # Check if locally administered (random/virtual MAC)
    try:
        first_byte = int(oui[:2], 16)
        if first_byte & 0x02:
            return "Virtual/Docker"
    except ValueError:
        pass
    return OUI_MAP.get(oui, "")


def get_friendly_name(container_name: str, mac: str = "",
                       device_type: str = "", ports: list = None) -> dict:
    """
    Get the best available friendly name and icon for a device.

    Priority order:
      1. Container name lookup (most specific)
      2. MAC OUI manufacturer
      3. Port-based category
      4. Device type string

    Args:
        container_name : Docker container name (e.g. 'cam1')
        mac            : MAC address string (e.g. 'aa:bb:cc:dd:ee:ff')
        device_type    : Classified type string from fingerprinting
        ports          : List of open port numbers

    Returns:
        dict with keys: friendly_name, icon, manufacturer, category
    """
    ports = ports or []

    # Layer 1: Container name
    if container_name.lower() in CONTAINER_FRIENDLY:
        name, icon = CONTAINER_FRIENDLY[container_name.lower()]
        manufacturer = get_manufacturer(mac) if mac else ""
        return {
            "friendly_name": name,
            "icon":          icon,
            "manufacturer":  manufacturer,
            "category":      device_type or "Smart Device",
            "source":        "name_library",
        }

    # Layer 2: MAC OUI
    manufacturer = get_manufacturer(mac) if mac else ""

    # Layer 3: Port fingerprint
    for port in [554, 631, 1883, 8883, 9100, 8888, 37777, 34567, 80, 443, 22]:
        if port in ports:
            category, icon = PORT_CATEGORY[port]
            friendly = f"{manufacturer} {category}".strip() if manufacturer else category
            return {
                "friendly_name": friendly,
                "icon":          icon,
                "manufacturer":  manufacturer,
                "category":      category,
                "source":        "port_lookup",
            }

    # Layer 4: Device type string
    icon = TYPE_ICONS.get(device_type, "📦")
    friendly = f"{manufacturer} Device".strip() if manufacturer else (device_type or "Unknown Device")
    return {
        "friendly_name": friendly,
        "icon":          icon,
        "manufacturer":  manufacturer,
        "category":      device_type or "Unknown",
        "source":        "type_fallback",
    }


def get_device_icon(container_name: str, device_type: str = "") -> str:
    """Quick helper — returns just the emoji icon for a device."""
    if container_name.lower() in CONTAINER_FRIENDLY:
        return CONTAINER_FRIENDLY[container_name.lower()][1]
    return TYPE_ICONS.get(device_type, "📦")


def enrich_device(device: dict) -> dict:
    """
    Add friendly_name, icon, manufacturer fields to a device dict.
    Works directly on the normalized device dict from the API.
    Modifies in-place and returns the dict.
    """
    info = get_friendly_name(
        container_name = device.get("name", ""),
        mac            = device.get("mac", ""),
        device_type    = device.get("type", ""),
        ports          = device.get("ports", []),
    )
    device["friendly_name"] = info["friendly_name"]
    device["icon"]          = info["icon"]
    device["manufacturer"]  = info["manufacturer"]
    return device


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Device Name Library Test ===\n")

    test_devices = [
        {"name": "cam1",        "mac": "C0:56:7B:AA:BB:CC", "type": "HTTP Device",          "ports": [80]},
        {"name": "printer",     "mac": "00:17:88:AA:BB:CC", "type": "Network Printer",       "ports": [631]},
        {"name": "thermo1",     "mac": "AA:BB:CC:DD:EE:FF", "type": "MQTT Sensor/Actuator",  "ports": [1883]},
        {"name": "chromecast",  "mac": "54:60:0A:AA:BB:CC", "type": "HTTP Device",           "ports": [80]},
        {"name": "lock1",       "mac": "02:AA:BB:CC:DD:EE", "type": "HTTP Device",           "ports": [80]},
        {"name": "nas",         "mac": "3C:5A:B4:AA:BB:CC", "type": "HTTP Device",           "ports": [80]},
        {"name": "bulb1",       "mac": "00:17:88:AA:BB:CC", "type": "MQTT Sensor/Actuator",  "ports": [1883]},
        {"name": "unknown_dev", "mac": "B8:27:EB:AA:BB:CC", "type": "Unknown IoT Device",    "ports": []},
    ]

    for d in test_devices:
        result = get_friendly_name(d["name"], d["mac"], d["type"], d["ports"])
        print(f"{result['icon']}  {d['name']:<15} → {result['friendly_name']:<28} "
              f"[{result['manufacturer'] or 'unknown vendor'}] "
              f"via:{result['source']}")

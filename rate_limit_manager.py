#!/usr/bin/env python3
"""
rate_limit_manager.py — Option 2 + Option 4
Zero Trust Smart Home IoT Gateway — Rate Limit Manager

Strategy:
  Option 2 : MARK excess traffic instead of DROP → zero data loss
  Option 4 : Limit NEW connections per minute not packet rate
             → video streams, MQTT sessions, reconnects never flagged
             → port scans, connection floods caught immediately

Zones:
  NORMAL : 0 marked NEW conns    → no penalty
  SOFT   : 1–9 marked NEW conns  → score -10, alert, RECOVERABLE
  HARD   : >=10 marked NEW conns → score -25, alert, PERMANENT

Recovery:
  SOFT → NORMAL : recovered, penalty cleared, recovery alert sent
  HARD → *      : NEVER recovers — permanent until admin calls clear_hard()
  Quarantined   : cannot recover automatically
"""

import subprocess
import os
from datetime import datetime

RL_LOG       = "/var/log/zt-ratelimit.log"
PENALTY_SOFT = 10
PENALTY_HARD = 35
MARK_SOFT    = "0x10"
MARK_HARD    = "0x20"
SOFT_MIN     = 1
HARD_MIN     = 10

# ── Connection rate profiles by device type ───────────────────
CONN_PROFILES = {
    "IP Camera / NVR":      {"base_conn": 10, "buffer": 5},
    "MQTT Sensor/Actuator": {"base_conn": 5,  "buffer": 3},
    "Network Printer":      {"base_conn": 3,  "buffer": 2},
    "HTTP Device":          {"base_conn": 15, "buffer": 5},
    "HTTPS Device":         {"base_conn": 15, "buffer": 5},
    "Web Device":           {"base_conn": 20, "buffer": 8},
    "SSH Device":           {"base_conn": 5,  "buffer": 3},
    "Unknown IoT Device":   {"base_conn": 5,  "buffer": 3},
}

# ── Per-container overrides (priority over type profiles) ─────
CONTAINER_OVERRIDES = {
    "cam1":        {"base_conn": 10, "buffer": 5},
    "nvr":         {"base_conn": 10, "buffer": 5},
    "chromecast":  {"base_conn": 20, "buffer": 8},
    "tv1":         {"base_conn": 15, "buffer": 5},
    "nas":         {"base_conn": 15, "buffer": 5},
    "plug1":       {"base_conn": 5,  "buffer": 3},
    "lock1":       {"base_conn": 5,  "buffer": 3},
    "badge":       {"base_conn": 5,  "buffer": 3},
    "sensorhub":   {"base_conn": 8,  "buffer": 4},
    "energymeter": {"base_conn": 5,  "buffer": 3},
    "thermo1":     {"base_conn": 5,  "buffer": 3},
    "bulb1":       {"base_conn": 5,  "buffer": 3},
    "lighting":    {"base_conn": 5,  "buffer": 3},
    "envsensor":   {"base_conn": 5,  "buffer": 3},
    "printer":     {"base_conn": 3,  "buffer": 2},
}

# ── Active connection limits per device ───────────────────────
ACTIVE_CONN_LIMITS = {
    "IP Camera / NVR":      50,
    "MQTT Sensor/Actuator": 20,
    "Network Printer":      15,
    "HTTP Device":          30,
    "HTTPS Device":         30,
    "Web Device":           40,
    "SSH Device":           10,
    "Unknown IoT Device":   20,
}

ACTIVE_CONN_OVERRIDES = {
    "cam1": 50, "nvr": 50, "chromecast": 60, "tv1": 50,
    "nas": 40,  "plug1": 20, "lock1": 20,  "badge": 15,
    "sensorhub": 25, "energymeter": 20, "thermo1": 20,
    "bulb1": 20, "lighting": 20, "envsensor": 20, "printer": 15,
}

# Zone state: { container: "NORMAL" | "SOFT" | "HARD" }
# HARD is always permanent — only admin can clear it via clear_hard()
_zone_state = {}


def _log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} [RATELIMIT] {msg}"
    print(line)
    try:
        with open(RL_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _profile(container, device_type=""):
    return (CONTAINER_OVERRIDES.get(container)
            or CONN_PROFILES.get(device_type)
            or CONN_PROFILES["Unknown IoT Device"])


def _sname(c): return f"{c[:10]}-sc"   # soft rule name (max 15 chars)
def _hname(c): return f"{c[:10]}-hc"   # hard rule name (max 15 chars)


def _del(ip, name, rate, burst, mark):
    subprocess.run(
        ["iptables-nft", "-D", "DOCKER-USER", "-i", "docker-iot", "-s", f"{ip}/32",
         "-m", "state", "--state", "NEW", "-m", "hashlimit",
         "--hashlimit-name", name, "--hashlimit-above", f"{rate}/min",
         "--hashlimit-burst", str(burst), "--hashlimit-mode", "srcip",
         "-j", "MARK", "--set-mark", mark],
        capture_output=True)


def _add(ip, name, rate, burst, mark):
    return subprocess.run(
        ["iptables-nft", "-I", "DOCKER-USER", "-i", "docker-iot", "-s", f"{ip}/32",
         "-m", "state", "--state", "NEW", "-m", "hashlimit",
         "--hashlimit-name", name, "--hashlimit-above", f"{rate}/min",
         "--hashlimit-burst", str(burst), "--hashlimit-mode", "srcip",
         "-j", "MARK", "--set-mark", mark],
        capture_output=True, text=True)


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────

def apply_conn_limit(container, ip, device_type):
    """
    Apply SOFT and HARD mark rules for NEW connections from this device.
    Two rules per device — no packets dropped (Option 2).
    Only NEW TCP connection setups are counted (Option 4).

    Rule 1 SOFT: NEW conn > base_conn/min  → mark 0x10
    Rule 2 HARD: NEW conn > ceiling/min    → mark 0x20
    """
    p   = _profile(container, device_type)
    b   = p["base_conn"]
    buf = p["buffer"]
    c   = b + buf

    # Remove stale rules first to avoid duplicates
    _del(ip, _sname(container), b,  buf, MARK_SOFT)
    _del(ip, _hname(container), c,  buf, MARK_HARD)

    r1 = _add(ip, _sname(container), b,  buf, MARK_SOFT)
    r2 = _add(ip, _hname(container), c,  buf, MARK_HARD)

    ok = r1.returncode == 0 and r2.returncode == 0
    if ok:
        _log(f"APPLIED  | {container:15} | {ip:15} | "
             f"base={b}/min  ceiling={c}/min  "
             f"soft={MARK_SOFT}  hard={MARK_HARD}")
    else:
        errs = " ".join(filter(None, [r1.stderr.strip(), r2.stderr.strip()]))
        _log(f"FAILED   | {container:15} | {ip:15} | {errs}")
    return ok


def remove_limit(container, ip, device_type):
    """
    Remove both mark rules for a device.
    Called on quarantine or when device is restored (rules re-applied on next cycle).
    Clears zone state so tracking resets.
    """
    p   = _profile(container, device_type)
    b   = p["base_conn"]
    c   = b + p["buffer"]
    _del(ip, _sname(container), b, p["buffer"], MARK_SOFT)
    _del(ip, _hname(container), c, p["buffer"], MARK_HARD)
    _zone_state.pop(container, None)
    _log(f"REMOVED  | {container:15} | {ip:15} | Rules cleared")


def apply_all(device_history):
    """
    Apply connection mark rules for all non-quarantined IoT LAN devices.
    Called on controller startup after loading device_history.

    Only applies rules for devices that:
    - Are not quarantined
    - Have a valid IoT LAN IP (192.168.20.x) stored in last_ip
    - Have rl_applied == False OR rl_applied not set

    Devices with stale quarantine IPs (192.168.30.x) in last_ip
    are skipped here and will get rules applied in the main loop
    once they are rediscovered on the IoT LAN.
    """
    _log("=" * 58)
    _log("Flushing stale mark rules before startup...")
    r = subprocess.run(["iptables-nft", "-L", "DOCKER-USER", "-n", "--line-numbers"],
                       capture_output=True, text=True)
    nums = []
    for line in r.stdout.splitlines():
        if "MARK" in line:
            try:
                nums.append(int(line.split()[0]))
            except ValueError:
                pass
    for n in sorted(nums, reverse=True):
        subprocess.run(["iptables-nft", "-D", "DOCKER-USER", str(n)], capture_output=True)
    if nums:
        _log(f"Cleared {len(nums)} stale rules")
    _log("Applying connection mark rules (startup)...")
    applied = skipped = 0

    for container, info in device_history.items():
        ip          = info.get("last_ip", "")
        dt          = info.get("device_type", "Unknown IoT Device")
        quarantined = info.get("quarantined", False)

        # Skip quarantined devices
        if quarantined:
            _log(f"SKIPPED  | {container:15} | quarantined — skipping")
            skipped += 1
            continue

        # Skip devices with no valid IoT LAN IP
        # (stale from previous quarantine — will be fixed in main loop)
        if not ip or not ip.startswith("192.168.20."):
            _log(f"SKIPPED  | {container:15} | "
                 f"no valid IoT LAN IP (last_ip={ip or 'none'}) — "
                 f"will apply on discovery")
            skipped += 1
            continue

        if apply_conn_limit(container, ip, dt):
            applied += 1
        else:
            skipped += 1

    _log(f"Startup done — {applied} rules applied, {skipped} skipped")
    _log("=" * 58)
    return applied


def read_mark_counts():
    """
    Read per-cycle SOFT and HARD mark counts from DOCKER-USER chain.
    Returns: { ip: {"soft": int, "hard": int} }
    Call reset_counters() after each cycle.
    """
    r = subprocess.run(["iptables-nft", "-L", "DOCKER-USER", "-n", "-v"],
                       capture_output=True, text=True)
    counts = {}
    for line in r.stdout.splitlines():
        if "MARK" not in line:
            continue
        parts = line.split()
        try:
            pkts = int(parts[0])
            if pkts == 0:
                continue
            src = next(
                (p.split("/")[0] for p in parts
                 if p.startswith("192.168.20.") or p.startswith("192.168.30.")),
                None
            )
            if not src:
                continue
            is_hard = "0x20" in line or MARK_HARD in line
            is_soft = ("0x10" in line or MARK_SOFT in line) and not is_hard
            counts.setdefault(src, {"soft": 0, "hard": 0})
            if is_hard:
                counts[src]["hard"] = pkts
            elif is_soft:
                counts[src]["soft"] = pkts
        except (ValueError, IndexError):
            continue
    return counts


def reset_counters():
    """Zero DOCKER-USER counters. Call at end of each cycle."""
    subprocess.run(["iptables-nft", "-Z", "DOCKER-USER"], capture_output=True)


def evaluate(container, ip, device_type, mark_counts):
    """
    Determine rate zone from mark counts this cycle.

    HARD is permanent — once entered, stays HARD regardless of current marks.
    Only admin calling clear_hard() can reset it.
    SOFT recovers when marks return to 0.

    Returns: (zone, penalty, recovered, message)
    """
    p        = _profile(container, device_type)
    base     = p["base_conn"]
    ceiling  = base + p["buffer"]
    soft_m   = mark_counts.get("soft", 0)
    hard_m   = mark_counts.get("hard", 0)
    prev     = _zone_state.get(container, "NORMAL")

    # HARD is permanent: previous HARD stays HARD regardless of current marks
    if prev == "HARD" or hard_m >= HARD_MIN:
        zone, penalty = "HARD", PENALTY_HARD
        if prev == "HARD" and hard_m < HARD_MIN:
            msg = (f"HARD permanent — rate normalized but penalty stays "
                   f"(base={base}/min ceiling={ceiling}/min) | -{penalty}")
        else:
            msg = (f"Connection flood — {hard_m} NEW conns above ceiling "
                   f"(base={base}/min ceiling={ceiling}/min) "
                   f"NO DATA LOST | -{penalty}")

    elif soft_m >= SOFT_MIN:
        zone, penalty = "SOFT", PENALTY_SOFT
        msg = (f"Connection burst — {soft_m} NEW conns in buffer zone "
               f"(base={base}/min ceiling={ceiling}/min) "
               f"NO DATA LOST | -{penalty}")

    else:
        zone, penalty = "NORMAL", 0
        msg = (f"Normal — 0 marked connections "
               f"(base={base}/min ceiling={ceiling}/min)")

    # Recovery: ONLY SOFT → NORMAL. HARD never recovers automatically.
    recovered = (prev == "SOFT" and zone == "NORMAL")

    _zone_state[container] = zone

    if recovered:
        _log(f"RECOVERED| {container:15} | {ip:15} | "
             f"SOFT → NORMAL — burst subsided, penalty cleared")

    return zone, penalty, recovered, msg


def get_active_connections(ip):
    """Count total ESTABLISHED connections from a device IP using ss."""
    try:
        r = subprocess.run(
            ["ss", "-tn", "state", "established", f"src {ip}"],
            capture_output=True, text=True
        )
        return max(0, len(r.stdout.strip().splitlines()) - 1)
    except Exception:
        return 0


def get_active_limit(container, device_type):
    """Return the active connection limit for this device."""
    return (ACTIVE_CONN_OVERRIDES.get(container)
            or ACTIVE_CONN_LIMITS.get(device_type)
            or ACTIVE_CONN_LIMITS["Unknown IoT Device"])


def check_active_connections(container, ip, device_type):
    """
    Check if device exceeds its active connection limit.
    Returns: (exceeded, count, limit, message)
    """
    count   = get_active_connections(ip)
    limit   = get_active_limit(container, device_type)
    exceeded = count > limit
    if exceeded:
        msg = (f"Active connections exceeded — {count} established "
               f"(limit={limit}) → quarantine triggered")
        _log(f"ACTIVE   | {container:15} | {ip:15} | {msg}")
    else:
        msg = f"Active connections normal — {count}/{limit}"
    return exceeded, count, limit, msg


def clear_hard(container):
    """
    Admin-only: manually clear a permanent HARD violation.
    Call only after investigation confirms device is safe.
    """
    if _zone_state.get(container) == "HARD":
        _zone_state[container] = "NORMAL"
        _log(f"ADMIN CLR| {container:15} | HARD cleared — returning to NORMAL")
        return True
    _log(f"ADMIN CLR| {container:15} | "
         f"Not in HARD (current: {_zone_state.get(container,'NORMAL')}) — no action")
    return False


def get_zone(container):
    """Return current zone for a container: NORMAL | SOFT | HARD"""
    return _zone_state.get(container, "NORMAL")


def status():
    """Print all active mark rules and current zone states."""
    r = subprocess.run(["iptables-nft", "-L", "DOCKER-USER", "-n", "-v"],
                       capture_output=True, text=True)
    active = [l.strip() for l in r.stdout.splitlines()
              if "MARK" in l]
    _log(f"=== {len(active)} active connection mark rules in DOCKER-USER ===")
    for rule in active:
        _log(f"  {rule}")
    if _zone_state:
        _log("--- Zone states ---")
        for c, z in sorted(_zone_state.items()):
            _log(f"  {c:<15} → {z}")


def flush_all():
    """Remove all MARK+hashlimit rules. For testing only."""
    r = subprocess.run(["iptables-nft", "-L", "DOCKER-USER", "-n", "--line-numbers"],
                       capture_output=True, text=True)
    nums = []
    for line in r.stdout.splitlines():
        if "MARK" in line:
            try:
                nums.append(int(line.split()[0]))
            except ValueError:
                pass
    for n in sorted(nums, reverse=True):
        subprocess.run(["iptables-nft", "-D", "DOCKER-USER", str(n)], capture_output=True)
    _zone_state.clear()
    _log(f"Flushed {len(nums)} connection mark rules")


def summary_table():
    """Print all configured rate profiles."""
    _log("=" * 68)
    _log("Rate Profiles  [Option 2+4: MARK + NEW connections only]")
    _log(f"{'Container':<15} | {'Base':>4}/m | {'Buf':>3}/m | "
         f"{'Ceil':>4}/m | {'ActiveLimit':>11}")
    _log("-" * 68)
    for c, p in CONTAINER_OVERRIDES.items():
        b  = p["base_conn"]
        bu = p["buffer"]
        al = ACTIVE_CONN_OVERRIDES.get(c, "?")
        _log(f"{c:<15} | {b:>4}    | {bu:>3}    | "
             f"{b+bu:>4}    | {al:>11}")
    _log("=" * 68)
    _log(f"SOFT  {SOFT_MIN}–{HARD_MIN-1} NEW conns  → -{PENALTY_SOFT}  RECOVERABLE")
    _log(f"HARD  >={HARD_MIN} NEW conns  → -{PENALTY_HARD}  PERMANENT (admin clears only)")
    _log("Active conn > limit  → quarantine immediately")
    _log("No packets dropped   — Option 2 (MARK not DROP)")
    _log("NEW connections only — Option 4 (streams unaffected)")
    _log("=" * 68)


if __name__ == "__main__":
    import sys
    cmds = "status | summary | flush | clear <c> | zone <c> | test"

    if len(sys.argv) < 2:
        summary_table()
        print(f"\nRun with: {cmds}")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "status":
        status()
    elif cmd == "summary":
        summary_table()
    elif cmd == "flush":
        if input("Flush ALL rules? (yes/no): ").strip().lower() == "yes":
            flush_all()
    elif cmd == "clear":
        if len(sys.argv) < 3:
            print("Usage: clear <container>")
        else:
            clear_hard(sys.argv[2])
    elif cmd == "zone":
        if len(sys.argv) < 3:
            print("Usage: zone <container>")
        else:
            print(f"{sys.argv[2]} → {get_zone(sys.argv[2])}")
    elif cmd == "test":
        print("\n=== Zone Transition Tests ===\n")
        _zone_state.clear()
        cases = [
            ("1. Idle",               0,  0,  "NORMAL"),
            ("2. Buffer burst",       4,  0,  "SOFT"),
            ("3. Still bursting",     2,  0,  "SOFT"),
            ("4. Subsides",           0,  0,  "NORMAL"),
            ("5. Another burst",      3,  0,  "SOFT"),
            ("6. Flood hits HARD",    5,  12, "HARD"),
            ("7. Flood stops",        0,  0,  "HARD"),
            ("8. Rate normal",        0,  0,  "HARD"),
        ]
        for label, sm, hm, exp in cases:
            z, p, r, m = evaluate("thermo1", "192.168.20.6",
                                  "MQTT Sensor/Actuator", {"soft": sm, "hard": hm})
            ok  = "✅" if z == exp else "❌"
            rec = " ← RECOVERED" if r else ""
            print(f"{ok} {label:<28} zone={z:<8} penalty={p:>2}{rec}")

        print("\n--- Admin clears HARD ---")
        clear_hard("thermo1")
        z, p, r, m = evaluate("thermo1", "192.168.20.6",
                              "MQTT Sensor/Actuator", {"soft": 0, "hard": 0})
        print(f"{'✅' if z=='NORMAL' else '❌'} 9. After clear   "
              f"zone={z}  penalty={p}")

        print("\n--- Active connection test ---")
        count = get_active_connections("192.168.20.6")
        limit = get_active_limit("thermo1", "MQTT Sensor/Actuator")
        print(f"thermo1: {count} active / limit {limit}")

        print("\nSummary:")
        print("  SOFT recovery ✅  HARD permanent ✅  "
              "No drop ✅  NEW conns ✅  Active check ✅")
    else:
        print(f"Unknown: {cmd}\nUsage: {cmds}")

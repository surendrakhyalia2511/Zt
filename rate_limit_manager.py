import re
import subprocess
import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.environ.get("APP_PATH", "/home/sk"))
from env_loader import env

RL_LOG = env("RL_LOG", "/var/log/zt-ratelimit.log")

# ── Zero-Data-Loss Design ─────────────────────────────────────────────────────
# Packets are NEVER dropped. Instead, excess connections are MARKED:
#   MARK 0x10 (hex 16) = SOFT zone  — above base rate, below ceiling
#   MARK 0x20 (hex 32) = HARD zone  — above ceiling rate
#
# Two iptables-nft rules per device (installed in DOCKER-USER chain):
#   Rule 1 (SOFT): hashlimit above base/min  → MARK 0x10
#   Rule 2 (HARD): hashlimit above ceiling/min → MARK 0x20
#
# Each cycle: read packet counters on MARK rules to count violations.
# Reset counters after reading so each cycle gets a fresh count.
# ─────────────────────────────────────────────────────────────────────────────

MARK_SOFT = "0x10"   # SOFT zone mark value
MARK_HARD = "0x20"   # HARD zone mark value

PENALTY_SOFT = 10    # score deduction for SOFT
PENALTY_HARD = 35    # score deduction for HARD

# Thresholds: how many MARKED packets = which zone
SOFT_MARK_MIN = int(env("SOFT_MARK_MIN", "1"))    # >= 1 marked pkt  → SOFT
HARD_MARK_MIN = int(env("HARD_MARK_MIN", "10"))   # >= 10 marked pkts → HARD

IOT_NET = env("IOT_NET", "192.168.20")

# ── Recovery ──────────────────────────────────────────────────────────────────
_zone_state    = {}   # { container: "NORMAL" | "SOFT" | "HARD" }
_normal_cycles = {}   # { container: consecutive_normal_cycle_count }
SOFT_RECOVERY_CYCLES = 2   # need 2 clean cycles to clear SOFT penalty

# ── Rate Profiles (base + buffer per device type) ─────────────────────────────
# base    = normal max NEW connections/min
# buffer  = extra above base before HARD kicks in
# ceiling = base + buffer  → HARD MARK threshold
RATE_PROFILES = {
    "IP Camera / NVR":      {"base": 500, "buffer": 100, "max_conn": 20},
    "MQTT Sensor/Actuator": {"base": 60,  "buffer": 20,  "max_conn": 3},
    "Network Printer":      {"base": 30,  "buffer": 10,  "max_conn": 5},
    "HTTP Device":          {"base": 100, "buffer": 30,  "max_conn": 10},
    "HTTPS Device":         {"base": 100, "buffer": 30,  "max_conn": 10},
    "Web Device":           {"base": 150, "buffer": 40,  "max_conn": 15},
    "SSH Device":           {"base": 50,  "buffer": 15,  "max_conn": 5},
    "Unknown IoT Device":   {"base": 50,  "buffer": 15,  "max_conn": 8},
}

# ── Per-Container Overrides ───────────────────────────────────────────────────
# Demo devices use LOW limits so test commands (25 connections) trigger them.
# base=5, ceiling=8 means: 7 conns → SOFT mark, 25 conns → HARD mark
CONTAINER_OVERRIDES = {
    # High-bandwidth (production values — not demo targets)
    "cam1"       : {"base": 500, "buffer": 100, "max_conn": 20},
    "nvr"        : {"base": 500, "buffer": 100, "max_conn": 20},
    "chromecast" : {"base": 300, "buffer": 60,  "max_conn": 15},
    "tv1"        : {"base": 200, "buffer": 50,  "max_conn": 15},
    # Demo targets — LOW limits
    "badge"      : {"base": 5,   "buffer": 3,   "max_conn": 5},
    "nas"        : {"base": 5,   "buffer": 3,   "max_conn": 20},
    "plug1"      : {"base": 5,   "buffer": 3,   "max_conn": 5},
    "lock1"      : {"base": 5,   "buffer": 3,   "max_conn": 5},
    "sensorhub"  : {"base": 10,  "buffer": 5,   "max_conn": 10},
    "energymeter": {"base": 10,  "buffer": 5,   "max_conn": 5},
    "thermo1"    : {"base": 10,  "buffer": 5,   "max_conn": 3},
    "bulb1"      : {"base": 10,  "buffer": 5,   "max_conn": 3},
    "lighting"   : {"base": 10,  "buffer": 5,   "max_conn": 3},
    "envsensor"  : {"base": 10,  "buffer": 5,   "max_conn": 3},
    "printer"    : {"base": 30,  "buffer": 10,  "max_conn": 5},
}


def _log(msg):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} [RATELIMIT] {msg}"
    print(line)
    try:
        with open(RL_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _get_profile(container, device_type):
    if container in CONTAINER_OVERRIDES:
        return CONTAINER_OVERRIDES[container]
    return RATE_PROFILES.get(device_type, RATE_PROFILES["Unknown IoT Device"])


def _rule_name(container, suffix=""):
    """Max 15 chars for hashlimit name."""
    return f"{container[:10]}{suffix}-rl"


def _remove_mark_rules(ip, container):
    """
    Remove both SOFT and HARD MARK rules for a device IP.
    Tries all known rule forms silently.
    """
    for mark, suffix in [(MARK_SOFT, "s"), (MARK_HARD, "h")]:
        name = _rule_name(container, suffix)
        # Remove without interface filter (current form)
        subprocess.run(
            ["iptables-nft", "-D", "DOCKER-USER",
             "-s", f"{ip}/32",
             "-m", "conntrack", "--ctstate", "NEW",
             "-m", "hashlimit",
             "--hashlimit-name",  name,
             "--hashlimit-above", "1/min",   # placeholder — actual value varies
             "--hashlimit-mode",  "srcip",
             "-j", "MARK", "--set-mark", mark],
            capture_output=True
        )
    # Brute-force flush by line number to catch any stale variants
    _flush_rules_for_ip(ip)


def _flush_rules_for_ip(ip):
    """Remove any DOCKER-USER rule matching this source IP (cleanup safety net)."""
    while True:
        result = subprocess.run(
            ["iptables-nft", "-L", "DOCKER-USER", "-n", "--line-numbers"],
            capture_output=True, text=True
        )
        found = None
        for line in result.stdout.splitlines():
            if f"{ip}/32" in line or f"{ip} " in line:
                try:
                    found = int(line.split()[0])
                    break
                except (ValueError, IndexError):
                    pass
        if found is None:
            break
        subprocess.run(
            ["iptables-nft", "-D", "DOCKER-USER", str(found)],
            capture_output=True
        )


def apply_mark_rules(container, ip, device_type):
    """
    Install TWO iptables-nft MARK rules per device — NO packet dropping.

    Rule 1 (SOFT): NEW connections above base/min → MARK 0x10
    Rule 2 (HARD): NEW connections above ceiling/min → MARK 0x20

    Packets continue flowing after being marked — zero data loss.
    Controller reads mark counters each cycle to detect violations.

    Args:
        container   : Docker container name
        ip          : Device IP on IoT LAN
        device_type : Classified device type string
    """
    profile = _get_profile(container, device_type)
    base    = profile["base"]
    ceiling = base + profile["buffer"]
    burst   = profile["buffer"]

    # Remove any stale rules first
    _remove_mark_rules(ip, container)

    success = True

    # ── Rule 1: SOFT mark (above base rate) ───────────────────
    r1 = subprocess.run(
        ["iptables-nft", "-I", "DOCKER-USER",
         "-s", f"{ip}/32",
         "-m", "conntrack", "--ctstate", "NEW",
         "-m", "hashlimit",
         "--hashlimit-name",  _rule_name(container, "s"),
         "--hashlimit-above", f"{base}/min",
         "--hashlimit-burst", str(burst),
         "--hashlimit-mode",  "srcip",
         "-j", "MARK", "--set-mark", MARK_SOFT],
        capture_output=True, text=True
    )

    if r1.returncode == 0:
        _log(f"MARK-SOFT| {container:15} | {ip:15} | "
             f"base={base}/min burst={burst} → MARK {MARK_SOFT}")
    else:
        _log(f"MARK-SOFT FAIL | {container:15} | {ip:15} | {r1.stderr.strip()}")
        success = False

    # ── Rule 2: HARD mark (above ceiling rate) ─────────────────
    r2 = subprocess.run(
        ["iptables-nft", "-I", "DOCKER-USER",
         "-s", f"{ip}/32",
         "-m", "conntrack", "--ctstate", "NEW",
         "-m", "hashlimit",
         "--hashlimit-name",  _rule_name(container, "h"),
         "--hashlimit-above", f"{ceiling}/min",
         "--hashlimit-burst", str(burst),
         "--hashlimit-mode",  "srcip",
         "-j", "MARK", "--set-mark", MARK_HARD],
        capture_output=True, text=True
    )

    if r2.returncode == 0:
        _log(f"MARK-HARD| {container:15} | {ip:15} | "
             f"ceiling={ceiling}/min burst={burst} → MARK {MARK_HARD}")
    else:
        _log(f"MARK-HARD FAIL | {container:15} | {ip:15} | {r2.stderr.strip()}")
        success = False

    return success


# Keep these as aliases so controller calls work unchanged
def apply_hard_limit(container, ip, device_type):
    return apply_mark_rules(container, ip, device_type)


def apply_conn_limit(container, ip, device_type):
    return apply_mark_rules(container, ip, device_type)


def remove_limit(container, ip, device_type):
    """Remove all MARK rules for a device. Called on quarantine/restore."""
    _remove_mark_rules(ip, container)
    _zone_state.pop(container, None)
    _normal_cycles.pop(container, None)
    _log(f"REMOVED  | {container:15} | {ip:15} | Mark rules cleared")


def apply_all(device_history):
    """
    Apply MARK rules for all non-quarantined IoT devices on startup.
    """
    iot_prefix = IOT_NET + "."
    _log("=" * 55)
    _log("Applying MARK rate limit rules (startup — zero data loss)...")
    count = 0; skipped = 0

    for container, info in device_history.items():
        ip          = info.get("last_ip", "")
        dev_type    = info.get("device_type", "Unknown IoT Device")
        quarantined = info.get("quarantined", False)

        if not ip or quarantined or not ip.startswith(iot_prefix):
            skipped += 1
            continue

        if apply_mark_rules(container, ip, dev_type):
            count += 1
        else:
            skipped += 1

    _log(f"Startup complete — {count} MARK rule pairs applied, {skipped} skipped")
    _log("=" * 55)
    return count


def read_mark_counts():
    """
    Read packet counters on MARK rules in DOCKER-USER chain.

    Returns: { ip_address: {"soft": N, "hard": M} }
    where soft = packets marked 0x10, hard = packets marked 0x20

    Replaces read_drop_counts() — counts marked packets not dropped ones.
    Uses --exact so counts are never abbreviated as 1K/1M.
    """
    result = subprocess.run(
        ["iptables-nft", "-L", "DOCKER-USER", "-n", "-v", "--exact"],
        capture_output=True, text=True
    )

    counts = {}   # { ip: {"soft": N, "hard": M} }

    for line in result.stdout.splitlines():
        # Only care about MARK lines
        if "MARK" not in line or "hashlimit" not in line:
            continue
        parts = line.split()
        try:
            pkts = int(parts[0])
            if pkts == 0:
                continue

            # Find source IP (a.b.c.d/32 format)
            src_ip = next(
                (p.split("/")[0] for p in parts
                 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", p)
                 and p not in ("0.0.0.0/0", "0.0.0.0")),
                None
            )
            if not src_ip:
                continue

            # Determine SOFT vs HARD by mark value in the line
            is_hard = MARK_HARD in line or "0x20" in line
            is_soft = MARK_SOFT in line or "0x10" in line

            if src_ip not in counts:
                counts[src_ip] = {"soft": 0, "hard": 0}

            if is_hard:
                counts[src_ip]["hard"] += pkts
            elif is_soft:
                counts[src_ip]["soft"] += pkts

        except (ValueError, IndexError):
            continue

    return counts


# Keep backward-compatible alias
def read_drop_counts():
    """Backward-compatible alias — returns total marked packets per IP."""
    raw = read_mark_counts()
    return {ip: v["soft"] + v["hard"] for ip, v in raw.items()}


def reset_counters():
    """Zero iptables-nft counters — called at end of each cycle."""
    subprocess.run(["iptables-nft", "-Z", "DOCKER-USER"], capture_output=True)


def evaluate(container, ip, device_type, packets_dropped):
    """
    Determine rate violation zone from mark counts.

    Args:
        packets_dropped : total marked packets this cycle (soft + hard combined)
                         OR pass read_mark_counts()[ip] dict for precision

    Returns: zone, penalty, recovered, message
    """
    profile = _get_profile(container, device_type)
    base    = profile["base"]
    ceiling = base + profile["buffer"]

    if packets_dropped < SOFT_MARK_MIN:
        zone    = "NORMAL"
        penalty = 0
        message = (
            f"Rate normal — {packets_dropped} marked packets "
            f"(base={base}/min, ceiling={ceiling}/min)"
        )
    elif packets_dropped < HARD_MARK_MIN:
        zone    = "SOFT"
        penalty = PENALTY_SOFT
        message = (
            f"Buffer zone — {packets_dropped} NEW conns above base "
            f"(base={base}/min ceiling={ceiling}/min) | -{penalty} pts"
        )
    else:
        zone    = "HARD"
        penalty = PENALTY_HARD
        message = (
            f"Connection flood — {packets_dropped} NEW conns above ceiling "
            f"(base={base}/min ceiling={ceiling}/min) NO DATA LOST | -{penalty} pts"
        )

    # ── Recovery tracking ─────────────────────────────────────
    prev_zone = _zone_state.get(container, "NORMAL")

    if zone == "NORMAL":
        _normal_cycles[container] = _normal_cycles.get(container, 0) + 1
    else:
        _normal_cycles[container] = 0

    soft_recovered = (
        prev_zone == "SOFT" and
        zone == "NORMAL" and
        _normal_cycles.get(container, 0) >= SOFT_RECOVERY_CYCLES
    )
    recovered = soft_recovered   # HARD never auto-recovers

    _zone_state[container] = zone

    if recovered:
        _normal_cycles[container] = 0
        _log(f"RECOVERED| {container:15} | {ip:15} | "
             f"SOFT → NORMAL after {SOFT_RECOVERY_CYCLES} clean cycles")

    return zone, penalty, recovered, message


def check_active_connections(container, ip, device_type):
    """
    Count ESTABLISHED TCP connections from a device using ss.

    This is SEPARATE from rate limiting:
    - Rate limit: counts NEW connection attempts per minute (hashlimit MARK)
    - Active connections: counts currently ESTABLISHED sessions (ss)

    A device might have low NEW conn rate but many open sessions, or
    a connection flood that slips through rate rules.
    """
    profile    = _get_profile(container, device_type)
    conn_limit = profile.get("max_conn", 8)

    try:
        result = subprocess.run(
            ["ss", "-tn", "state", "established", f"src {ip}"],
            capture_output=True, text=True
        )
        lines      = [l for l in result.stdout.splitlines() if l.strip()]
        conn_count = max(0, len(lines) - 1)   # subtract header row
    except Exception as e:
        _log(f"CONN-CHK | {container:15} | {ip:15} | ss failed: {e}")
        return False, 0, conn_limit, f"ss error: {e}"

    exceeded = conn_count > conn_limit
    if exceeded:
        message = (
            f"Active connection flood — {conn_count} established "
            f"connections exceeds limit={conn_limit}"
        )
        _log(f"CONN-OVR | {container:15} | {ip:15} | {message}")
    else:
        message = f"Active connections OK — {conn_count}/{conn_limit}"

    return exceeded, conn_count, conn_limit, message


def status():
    result = subprocess.run(
        ["iptables-nft", "-L", "DOCKER-USER", "-n", "-v", "--exact"],
        capture_output=True, text=True
    )
    soft_rules = [l.strip() for l in result.stdout.splitlines()
                  if "MARK" in l and MARK_SOFT in l]
    hard_rules = [l.strip() for l in result.stdout.splitlines()
                  if "MARK" in l and MARK_HARD in l]
    _log(f"=== {len(soft_rules)} SOFT mark rules, {len(hard_rules)} HARD mark rules ===")
    _log("=" * 55)


def flush_all():
    """Remove all MARK rules from DOCKER-USER chain."""
    result = subprocess.run(
        ["iptables-nft", "-L", "DOCKER-USER", "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    to_delete = []
    for line in result.stdout.splitlines():
        if "MARK" in line:
            try:
                to_delete.append(int(line.split()[0]))
            except ValueError:
                pass
    for num in sorted(to_delete, reverse=True):
        subprocess.run(
            ["iptables-nft", "-D", "DOCKER-USER", str(num)],
            capture_output=True
        )
    _zone_state.clear()
    _normal_cycles.clear()
    _log(f"Flushed {len(to_delete)} MARK rules from DOCKER-USER")


def summary_table():
    _log("=" * 80)
    _log("Rate Limit Profile Summary (MARK-based — zero data loss)")
    _log(f"{'Container':<15} | {'Base':>6} | {'Buffer':>6} | {'Ceiling':>8} | MaxConn")
    _log("-" * 80)
    for container, profile in CONTAINER_OVERRIDES.items():
        base    = profile["base"]
        buf     = profile["buffer"]
        ceiling = base + buf
        mc      = profile.get("max_conn", "?")
        _log(f"{container:<15} | {base:>4}/m | {buf:>4}/m | {ceiling:>6}/m | {mc:>7}")
    _log("=" * 80)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "status":    status()
        elif cmd == "summary": summary_table()
        elif cmd == "flush":
            if input("Flush ALL mark rules? (yes/no): ").lower() == "yes":
                flush_all()
        elif cmd == "test":
            print("\n=== Test: evaluate() — MARK zones ===")
            for n, drops in [(0, "NORMAL"), (5, "SOFT"), (25, "HARD"), (0, "recover-1"), (0, "recover-2")]:
                z, p, r, m = evaluate("badge", "192.168.20.x", "HTTP Device", n)
                print(f"  {drops:10} {n:3} marks → zone={z:6} penalty={p:2} recovered={r} | {m[:60]}")
        else:
            print("Usage: python3 rate_limit_manager.py [status|summary|flush|test]")
    else:
        summary_table()

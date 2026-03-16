#!/usr/bin/env python3
"""
scoring.py
Zero Trust IoT Gateway — Trust Scoring Engine

Two outcomes only: TRUSTED (score >= 40) or QUARANTINE (score < 40)

Score deductions:
  -20  IoT device (always)
  -10  Unknown vendor
  -50  Scanning detected (device sending to many destinations)
  -40  Under active attack (Kali/attacker targeting this device)
  -20  High connections > 10
  -10  Medium connections > 5
  -10  Previously quarantined
  -30  Currently in quarantine zone
  -10  Rate SOFT violation (buffer zone)
  -35  Rate HARD violation (ceiling exceeded) → score drops below 40 → quarantine
  -50  East-west lateral movement attempt → immediate quarantine
"""

SCORE_THRESHOLD = 40


def calculate_trust_score(device):
    """
    Calculate trust score for a device from its history record.

    Args:
        device : dict — device history entry from device_history.json

    Returns:
        score   : int  — trust score (0-100)
        reasons : list — human-readable list of applied deductions
    """
    score   = 100
    reasons = []

    # ── Static deductions ─────────────────────────────────────
    score -= 20
    reasons.append("IoT device (-20)")

    vendor = device.get("vendor", "")
    if not vendor or "Unknown" in vendor or "locally" in vendor:
        score -= 10
        reasons.append("Unknown vendor (-10)")

    # ── Behavioral deductions ─────────────────────────────────
    if device.get("scanning", False):
        score -= 50
        reasons.append("Scanning detected (-50)")

    if device.get("under_attack", False):
        score -= 40
        reasons.append("Under active attack (-40)")

    conn = device.get("connections", 0)
    if conn > 10:
        score -= 20
        reasons.append(f"High connections {conn} (-20)")
    elif conn > 5:
        score -= 10
        reasons.append(f"Medium connections {conn} (-10)")

    if device.get("east_west", False):
        score -= 50
        reasons.append("East-west lateral movement (-50)")

    # ── History deductions ────────────────────────────────────
    if device.get("quarantined_before", False):
        score -= 10
        reasons.append("Previously quarantined (-10)")

    if device.get("quarantined", False):
        score -= 30
        reasons.append("Currently in quarantine (-30)")

    # ── Rate limit penalty ────────────────────────────────────
    # SOFT = -10 (recoverable, stays TRUSTED)
    # HARD = -35 (permanent, drops below threshold → quarantine)
    rl_penalty = device.get("rl_penalty", 0)
    if rl_penalty > 0:
        zone_label = "buffer" if rl_penalty == 10 else "exceeded"
        score -= rl_penalty
        reasons.append(f"Rate violation [{zone_label}] (-{rl_penalty})")

    return score, reasons


def get_status(score, quarantined):
    """
    Return display status string.
    Only two real states: TRUSTED or QUARANTINE.
    IN QUARANTINE is displayed when device is physically in quarantine zone.
    """
    if quarantined:
        return "🔒 IN QUARANTINE"
    elif score >= SCORE_THRESHOLD:
        return "✅ TRUSTED"
    else:
        return "🚨 QUARANTINE"

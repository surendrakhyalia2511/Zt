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

Persistent score:
  Score is saved to device_history.json after every cycle.
  Fields saved: trust_score, score_reasons, score_updated_at, score_history[]
  score_history keeps last 20 scores for trend analysis in dashboard.
"""

from datetime import datetime

SCORE_THRESHOLD  = 40
MAX_SCORE_HISTORY = 20    # keep last N scores per device


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
    rl_penalty = device.get("rl_penalty", 0)
    if rl_penalty > 0:
        zone_label = "buffer" if rl_penalty == 10 else "exceeded"
        score -= rl_penalty
        reasons.append(f"Rate violation [{zone_label}] (-{rl_penalty})")

    return max(0, score), reasons


def persist_score(device: dict, score: int, reasons: list) -> dict:
    """
    Save the calculated score back into the device history dict.
    Updates trust_score, score_reasons, score_updated_at, score_history.

    Args:
        device  : device history dict (modified in place)
        score   : calculated trust score
        reasons : list of reason strings

    Returns:
        device dict with score fields updated
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Update current score fields
    device["trust_score"]      = score
    device["score_reasons"]    = reasons
    device["score_updated_at"] = now

    # Append to rolling score history
    history = device.get("score_history", [])
    history.append({
        "score":  score,
        "ts":     now,
        "reason": reasons[0] if reasons else "",
    })

    # Keep only last N entries
    if len(history) > MAX_SCORE_HISTORY:
        history = history[-MAX_SCORE_HISTORY:]

    device["score_history"] = history

    # Track min/max/baseline for trend detection
    scores = [h["score"] for h in history]
    device["score_min"]  = min(scores)
    device["score_max"]  = max(scores)
    device["score_avg"]  = round(sum(scores) / len(scores), 1)

    # Trend: compare current to previous score
    if len(history) >= 2:
        prev = history[-2]["score"]
        if score < prev:
            device["score_trend"] = "down"
        elif score > prev:
            device["score_trend"] = "up"
        else:
            device["score_trend"] = "stable"
    else:
        device["score_trend"] = "stable"

    return device


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


def get_trend_arrow(trend: str) -> str:
    """Return visual trend indicator."""
    return {"up": "↑", "down": "↓", "stable": "→"}.get(trend, "→")

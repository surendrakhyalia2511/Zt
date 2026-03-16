#!/bin/bash
# behavior_monitor.sh
# Zero Trust IoT Gateway — Continuous Background Behavioral Monitor
#
# Runs independently from zt_controller.py as a separate process.
# Monitors ens37 and docker-iot bridge in real-time.
# Writes detected events to EVENTS_FILE in JSON Lines format.
# Controller reads and clears EVENTS_FILE each cycle.
#
# Events written:
#   SCAN        — external attacker scanning IoT devices
#   EAST_WEST   — IoT device attempting lateral movement
#
# Usage:
#   sudo bash behavior_monitor.sh &       ← background from controller
#   sudo bash behavior_monitor.sh         ← standalone test

EVENTS_FILE="/var/run/zt-monitor-events.jsonl"
LOG_FILE="/var/log/zt-behavior.log"
IOT_NET="192.168.20"
TRUSTED_NET="192.168.10"
SCAN_THRESHOLD=3
CAPTURE_WINDOW=2   # seconds per capture — shorter = more responsive

# ── Ensure events file exists and is writable ────────────────
touch "$EVENTS_FILE"
chmod 666 "$EVENTS_FILE"

_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] $1" | tee -a "$LOG_FILE"
}

_write_event() {
    # Append one JSON line to events file atomically
    echo "$1" >> "$EVENTS_FILE"
}

_log "Behavioral monitor started (PID=$$)"
_log "Watching ens37 (external scan) + docker-iot (east-west)"
_log "Events file: $EVENTS_FILE"
_log "Capture window: ${CAPTURE_WINDOW}s  Scan threshold: ${SCAN_THRESHOLD}"

# ── Main monitoring loop ─────────────────────────────────────
while true; do

    TS=$(date '+%Y-%m-%d %H:%M:%S')

    # ── Capture 1: ens37 — external attacker scanning IoT ────
    ENS37_OUT=$(timeout "$CAPTURE_WINDOW" tcpdump \
        -i ens37 -nn -q \
        "src net ${TRUSTED_NET}.0/24 and dst net ${IOT_NET}.0/24" \
        2>/dev/null)

    # Build scan map: src_ip -> unique dst_ips
    declare -A SCAN_MAP

    while IFS= read -r line; do
        if [[ "$line" == *"IP"* ]]; then
            # Extract src and dst IPs
            src=$(echo "$line" | grep -oP 'IP \K[\d.]+')
            dst=$(echo "$line" | grep -oP '> \K[\d.]+' | head -1)
            if [[ -n "$src" && -n "$dst" ]]; then
                SCAN_MAP["$src"]+="$dst "
            fi
        fi
    done <<< "$ENS37_OUT"

    for src_ip in "${!SCAN_MAP[@]}"; do
        # Count unique destinations
        unique_dsts=$(echo "${SCAN_MAP[$src_ip]}" | tr ' ' '\n' | sort -u | grep -v '^$')
        count=$(echo "$unique_dsts" | grep -c .)

        if [[ "$count" -ge "$SCAN_THRESHOLD" ]]; then
            # Build JSON array of targets
            targets_json=$(echo "$unique_dsts" | \
                python3 -c "import sys,json; print(json.dumps(sys.stdin.read().split()))" 2>/dev/null \
                || echo '[]')

            event="{\"type\":\"SCAN\",\"src_ip\":\"${src_ip}\",\"targets\":${targets_json},\"count\":${count},\"ts\":\"${TS}\"}"
            _write_event "$event"
            _log "SCAN DETECTED: ${src_ip} → ${count} IoT devices"
        fi
    done

    unset SCAN_MAP

    # ── Capture 2: docker-iot — east-west lateral movement ───
    BRIDGE_OUT=$(timeout "$CAPTURE_WINDOW" tcpdump \
        -i docker-iot -nn -q -c 200 \
        "src net ${IOT_NET}.0/24 and dst net ${IOT_NET}.0/24" \
        2>/dev/null)

    declare -A EW_MAP

    while IFS= read -r line; do
        if [[ "$line" == *"IP"* ]]; then
            src=$(echo "$line" | grep -oP 'IP \K[\d.]+')
            dst=$(echo "$line" | grep -oP '> \K[\d.]+' | head -1)
            if [[ -n "$src" && -n "$dst" && "$src" != "$dst" ]]; then
                if [[ "$src" == ${IOT_NET}.* && "$dst" == ${IOT_NET}.* ]]; then
                    EW_MAP["$src"]+="$dst "
                fi
            fi
        fi
    done <<< "$BRIDGE_OUT"

    for src_ip in "${!EW_MAP[@]}"; do
        unique_dsts=$(echo "${EW_MAP[$src_ip]}" | tr ' ' '\n' | sort -u | grep -v '^$')
        count=$(echo "$unique_dsts" | grep -c .)

        dst_json=$(echo "$unique_dsts" | \
            python3 -c "import sys,json; print(json.dumps(sys.stdin.read().split()))" 2>/dev/null \
            || echo '[]')

        event="{\"type\":\"EAST_WEST\",\"src_ip\":\"${src_ip}\",\"dst_ips\":${dst_json},\"count\":${count},\"ts\":\"${TS}\"}"
        _write_event "$event"
        _log "EAST-WEST: ${src_ip} → ${count} IoT device(s)"
    done

    unset EW_MAP

    # No sleep — loop immediately for continuous coverage
    # The capture windows themselves provide the timing

done

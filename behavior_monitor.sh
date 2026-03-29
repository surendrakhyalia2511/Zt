#!/bin/bash
# behavior_monitor.sh
# Zero Trust IoT Gateway — Continuous Background Behavioral Monitor
#
# BUG FIXES:
#   1. declare -A arrays must be declared OUTSIDE the capture parse section
#      and explicitly unset+redeclared each iteration — bash associative
#      arrays declared inside process substitution or subshells are lost.
#   2. East-west events now written even for count=1 (not just count>=threshold)
#      since ANY IoT→IoT traffic is suspicious lateral movement.
#   3. Added explicit unset before each redeclare to avoid stale entries
#      accumulating across loop iterations.
#   4. grep -c can return exit code 1 (no matches) which stops script with
#      set -e — use `|| true` guards.

EVENTS_FILE="/var/run/zt-monitor-events.jsonl"
LOG_FILE="/var/log/zt-behavior.log"
IOT_NET="192.168.20"
TRUSTED_NET="192.168.10"
SCAN_THRESHOLD=3
CAPTURE_WINDOW=2   # seconds per capture

# ── Ensure events file exists and is writable ────────────────
touch "$EVENTS_FILE"
chmod 666 "$EVENTS_FILE"

_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] $1" | tee -a "$LOG_FILE"
}

_write_event() {
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
    # BUG FIX: capture from TRUSTED_NET (Kali/attack machine) to IoT
    ENS37_OUT=$(timeout "$CAPTURE_WINDOW" tcpdump \
        -i ens37 -nn -q \
        "src net ${TRUSTED_NET}.0/24 and dst net ${IOT_NET}.0/24" \
        2>/dev/null) || true

    # BUG FIX: declare -A OUTSIDE the while-read loop, unset first
    unset SCAN_MAP
    declare -A SCAN_MAP

    while IFS= read -r line; do
        [[ "$line" != *"IP"* ]] && continue
        # Parse: "HH:MM:SS.us IP src.port > dst.port: ..."
        src=$(echo "$line" | grep -oP '(?<=IP )[\d.]+' | head -1)
        dst=$(echo "$line" | grep -oP '(?<=> )[\d.]+' | head -1)
        if [[ -n "$src" && -n "$dst" ]]; then
            # Strip port from IPs (tcpdump shows 192.168.20.3.80 format)
            src_ip=$(echo "$src" | cut -d. -f1-4)
            dst_ip=$(echo "$dst" | cut -d. -f1-4)
            if [[ "$src_ip" == ${TRUSTED_NET}.* && "$dst_ip" == ${IOT_NET}.* ]]; then
                # Build space-separated unique dst list per src
                if [[ -z "${SCAN_MAP[$src_ip]+x}" ]]; then
                    SCAN_MAP[$src_ip]="$dst_ip"
                elif [[ "${SCAN_MAP[$src_ip]}" != *"$dst_ip"* ]]; then
                    SCAN_MAP[$src_ip]+=" $dst_ip"
                fi
            fi
        fi
    done <<< "$ENS37_OUT"

    for src_ip in "${!SCAN_MAP[@]}"; do
        unique_dsts=$(echo "${SCAN_MAP[$src_ip]}" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')
        count=$(echo "${SCAN_MAP[$src_ip]}" | tr ' ' '\n' | sort -u | grep -cv '^$' || true)

        if [[ "$count" -ge "$SCAN_THRESHOLD" ]]; then
            targets_json=$(echo "$unique_dsts" | tr ' ' '\n' | grep -v '^$' | \
                python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null \
                || echo '[]')

            event="{\"type\":\"SCAN\",\"src_ip\":\"${src_ip}\",\"targets\":${targets_json},\"count\":${count},\"ts\":\"${TS}\"}"
            _write_event "$event"
            _log "SCAN DETECTED: ${src_ip} → ${count} IoT devices"
        fi
    done

    # ── Capture 2: docker-iot — east-west lateral movement ───
    BRIDGE_OUT=$(timeout "$CAPTURE_WINDOW" tcpdump \
        -i docker-iot -nn -q -c 500 \
        "src net ${IOT_NET}.0/24 and dst net ${IOT_NET}.0/24" \
        2>/dev/null) || true

    # BUG FIX: unset before redeclare each iteration
    unset EW_MAP
    declare -A EW_MAP

    while IFS= read -r line; do
        [[ "$line" != *"IP"* ]] && continue
        src=$(echo "$line" | grep -oP '(?<=IP )[\d.]+' | head -1)
        dst=$(echo "$line" | grep -oP '(?<=> )[\d.]+' | head -1)
        if [[ -n "$src" && -n "$dst" ]]; then
            src_ip=$(echo "$src" | cut -d. -f1-4)
            dst_ip=$(echo "$dst" | cut -d. -f1-4)
            if [[ "$src_ip" == ${IOT_NET}.* && "$dst_ip" == ${IOT_NET}.* && "$src_ip" != "$dst_ip" ]]; then
                if [[ -z "${EW_MAP[$src_ip]+x}" ]]; then
                    EW_MAP[$src_ip]="$dst_ip"
                elif [[ "${EW_MAP[$src_ip]}" != *"$dst_ip"* ]]; then
                    EW_MAP[$src_ip]+=" $dst_ip"
                fi
            fi
        fi
    done <<< "$BRIDGE_OUT"

    for src_ip in "${!EW_MAP[@]}"; do
        unique_dsts=$(echo "${EW_MAP[$src_ip]}" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')
        count=$(echo "${EW_MAP[$src_ip]}" | tr ' ' '\n' | sort -u | grep -cv '^$' || true)

        if [[ "$count" -ge 1 ]]; then
            dst_json=$(echo "$unique_dsts" | tr ' ' '\n' | grep -v '^$' | \
                python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null \
                || echo '[]')

            event="{\"type\":\"EAST_WEST\",\"src_ip\":\"${src_ip}\",\"dst_ips\":${dst_json},\"count\":${count},\"ts\":\"${TS}\"}"
            _write_event "$event"
            _log "EAST-WEST: ${src_ip} → ${count} IoT device(s): ${unique_dsts}"
        fi
    done

    # Short sleep to avoid spinning at 100% CPU between captures
    sleep 0.1

done

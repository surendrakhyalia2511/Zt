#!/bin/bash
# quarantine_device.sh
# Usage: ./quarantine_device.sh <container_name> [ip_address]
# BUG FIX: was only reading $1 (container), ignoring $2 (ip)
# dashboard_api.py and quarantine_manager.py both pass ip as $2
# The ip arg is used here for logging; iptables cleanup is handled
# by rate_limit_manager.remove_limit() called from quarantine_manager.py

CONTAINER=$1
IP=${2:-"unknown"}

if [ -z "$CONTAINER" ]; then
    echo "Usage: ./quarantine_device.sh <container_name> [ip_address]"
    exit 1
fi

echo "🚨 Quarantining $CONTAINER (IP: $IP)..."

# Disconnect from IoT network (ignore error if not connected)
docker network disconnect iot-lan "$CONTAINER" 2>/dev/null || true

# Connect to quarantine network (ignore error if already connected)
docker network connect quarantine-lan "$CONTAINER" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ $CONTAINER moved to quarantine network (192.168.30.0/24)"
    echo "❌ IoT LAN access blocked"
    echo "✅ Quarantine network connected"
else
    echo "⚠️  docker network connect failed — container may already be quarantined"
fi

# Flush nft raw PREROUTING to avoid stale drop rules interfering with monitoring
nft flush chain ip raw PREROUTING 2>/dev/null || true

echo "✅ Quarantine complete for $CONTAINER"

#!/bin/bash
CONTAINER=$1   # container name e.g. cam1

if [ -z "$CONTAINER" ]; then
    echo "Usage: ./quarantine_device.sh <container_name>"
    exit 1
fi

echo "🚨 Quarantining $CONTAINER..."

# Disconnect from IoT network
docker network disconnect iot-lan $CONTAINER

# Connect to quarantine network
docker network connect quarantine-lan $CONTAINER

echo "✅ $CONTAINER moved to quarantine network (192.168.30.0/24)"
echo "❌ LAN access blocked"
echo "✅ Internet only allowed"

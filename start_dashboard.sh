#!/bin/bash
# start_dashboard.sh
# Starts ZeroTrust dashboard API with HTTPS

CERT="/home/sk/certs/gateway.crt"
KEY="/home/sk/certs/gateway.key"

echo "Starting ZeroTrust Dashboard (HTTPS)..."
echo "Access at: https://192.168.35.136:8443"
echo ""

cd /home/sk
python3 -m uvicorn dashboard_api:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-certfile "$CERT" \
    --ssl-keyfile  "$KEY" \
    --log-level info

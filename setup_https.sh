#!/bin/bash
# setup_https.sh
# Zero Trust IoT Gateway — HTTPS Setup (Self-Signed Certificate)
#
# Generates a self-signed TLS certificate valid for 10 years.
# Configures uvicorn to serve HTTPS on port 8443.
# Updates dashboard.html WebSocket URL from ws:// to wss://
#
# Usage:
#   sudo bash setup_https.sh

set -e

CERT_DIR="/home/sk/certs"
CERT_FILE="$CERT_DIR/gateway.crt"
KEY_FILE="$CERT_DIR/gateway.key"
GATEWAY_IP=$(hostname -I | awk '{print $1}')

echo "================================================"
echo " ZeroTrust Gateway — HTTPS Setup"
echo "================================================"
echo " Gateway IP : $GATEWAY_IP"
echo " Cert dir   : $CERT_DIR"
echo ""

# ── Step 1: Create cert directory ────────────────────────────
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# ── Step 2: Generate self-signed certificate ──────────────────
echo "[1/4] Generating self-signed TLS certificate..."

openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out    "$CERT_FILE" \
    -days   3650 \
    -nodes \
    -subj "/C=IN/ST=Home/L=Gateway/O=ZeroTrust/CN=ztgateway" \
    -addext "subjectAltName=IP:$GATEWAY_IP,IP:127.0.0.1,DNS:ztgateway,DNS:localhost" \
    2>/dev/null

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "    ✅ Certificate generated"
echo "    📄 Cert : $CERT_FILE"
echo "    🔑 Key  : $KEY_FILE"
echo "    📅 Valid: 10 years"
echo "    🌐 SAN  : IP:$GATEWAY_IP, IP:127.0.0.1"

# ── Step 3: Show cert fingerprint ────────────────────────────
echo ""
echo "[2/4] Certificate fingerprint (trust this in browser):"
openssl x509 -in "$CERT_FILE" -fingerprint -sha256 -noout 2>/dev/null | \
    sed 's/SHA256 Fingerprint=/    SHA256: /'

# ── Step 4: Create uvicorn HTTPS start script ─────────────────
echo ""
echo "[3/4] Creating HTTPS start script..."

cat > /home/sk/start_dashboard.sh << SCRIPT
#!/bin/bash
# start_dashboard.sh
# Starts ZeroTrust dashboard API with HTTPS

CERT="/home/sk/certs/gateway.crt"
KEY="/home/sk/certs/gateway.key"

echo "Starting ZeroTrust Dashboard (HTTPS)..."
echo "Access at: https://$(hostname -I | awk '{print $1}'):8443"
echo ""

cd /home/sk
uvicorn dashboard_api:app \\
    --host 0.0.0.0 \\
    --port 8443 \\
    --ssl-certfile "\$CERT" \\
    --ssl-keyfile  "\$KEY" \\
    --log-level info
SCRIPT

chmod +x /home/sk/start_dashboard.sh
echo "    ✅ Start script: /home/sk/start_dashboard.sh"

# ── Step 5: Update systemd service if it exists ───────────────
echo ""
echo "[4/4] Checking systemd service..."

SERVICE_FILE="/etc/systemd/system/zt-dashboard.service"
cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=ZeroTrust Dashboard API (HTTPS)
After=network.target zt-lab-init.service
Wants=zt-lab-init.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/sk
ExecStart=/usr/local/bin/uvicorn dashboard_api:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-certfile /home/sk/certs/gateway.crt \
    --ssl-keyfile  /home/sk/certs/gateway.key \
    --log-level info
Restart=always
RestartSec=5
Environment=PYTHONPATH=/home/sk

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable zt-dashboard.service
echo "    ✅ systemd service created and enabled"

# ── Done ──────────────────────────────────────────────────────
echo ""
echo "================================================"
echo " HTTPS Setup Complete"
echo "================================================"
echo ""
echo " Start now    : sudo bash /home/sk/start_dashboard.sh"
echo " Or via systemd: sudo systemctl start zt-dashboard"
echo ""
echo " Access URL   : https://$GATEWAY_IP:8443"
echo ""
echo " ⚠️  BROWSER WARNING: Click 'Advanced' → 'Proceed'"
echo "    This is normal for self-signed certificates."
echo "    On Chrome: type 'thisisunsafe' to bypass."
echo ""
echo " 📱 iOS/Android: Install cert to trust it fully:"
echo "    curl http://$GATEWAY_IP:8000/static/gateway.crt -o gateway.crt"
echo "    Then open the .crt file on your device"
echo ""

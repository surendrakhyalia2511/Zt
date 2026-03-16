#!/bin/bash
exec >> /var/log/zt-lab-init.log 2>&1
echo "=== ZT Lab Init $(date) ==="

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.bridge.bridge-nf-call-iptables=1

sleep 10

cd /home/sk
docker compose up -d
echo "Docker compose exit: $?"

sleep 5
netfilter-persistent reload
echo "Firewall reload exit: $?"
echo "=== Init complete ==="

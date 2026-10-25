#!/bin/sh
set -e

CONFIG_DIR="/data/config"
WG_DIR="/data/wireguard"
mkdir -p "$CONFIG_DIR" "$WG_DIR"

if [ -f "$WG_DIR/wg0.conf" ]; then
    echo "[*] Using existing WireGuard config"
    cp "$WG_DIR/wg0.conf" /etc/wireguard/wg0.conf
else
    echo "[!] No WireGuard config found at $WG_DIR/wg0.conf"
    echo "[!] Please add your config via the dashboard"
    cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
PrivateKey = 
Address = 10.0.0.2/24

[Peer]
PublicKey = 
Endpoint = 
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF
    cp /etc/wireguard/wg0.conf "$WG_DIR/wg0.conf"
fi

wg-quick up wg0 2>/dev/null || echo "[!] wg-quick failed — check config"

sleep 2
WG_IP=$(ip -4 addr show wg0 2>/dev/null | grep -o 'inet [0-9.]*' | awk '{print $2}' | head -1)
echo "[*] WireGuard IP: ${WG_IP:-not connected}"

# Policy routing: replies to connections that came through the tunnel
# MUST return via wg0, not via the container's default (eth0) route.
if [ -n "$WG_IP" ]; then
    ip route replace default via 10.0.0.1 dev wg0 table 200 2>/dev/null || true
    if ! ip rule show | grep -q "from $WG_IP lookup 200"; then
        ip rule add from "$WG_IP" lookup 200 2>/dev/null || true
    fi
    echo "[*] Policy routing configured for $WG_IP"
fi

if [ -f /etc/haproxy/haproxy.cfg ]; then
    haproxy -f /etc/haproxy/haproxy.cfg -p /var/run/haproxy.pid 2>/dev/null || true
fi

cd /app
exec python3 app.py --host 0.0.0.0 --port 8081

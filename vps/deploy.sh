#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-}"
echo "=== tunnel-wg Server Deploy ==="

for cmd in docker docker-compose curl; do
  if ! command -v $cmd &>/dev/null; then
    echo "Error: $cmd not found. Install Docker first."
    exit 1
  fi
done

if [ -z "$DOMAIN" ]; then
  DOMAIN=$(curl -s https://api.ipify.org)
fi
export VPS_PUBLIC_IP="$DOMAIN"

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.forwarding=1

update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true

cd "$(dirname "$0")"

# Pre-seed an empty wg0.conf so the wireguard container starts cleanly
mkdir -p wireguard
if [ ! -f wireguard/wg0.conf ]; then
  cat > wireguard/wg0.conf << 'EOF'
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
SaveConfig = false

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
EOF
fi

docker compose build
docker compose up -d

echo "✅ tunnel-wg deployed!"
echo "   Dashboard: http://${DOMAIN}:8080"
echo "   WireGuard: udp://${DOMAIN}:51820"
echo ""
echo "⚠️  Asegúrate de abrir en el firewall de tu proveedor:"
echo "   - 51820/udp   (WireGuard)"
echo "   - 8080/tcp    (Dashboard — restringir a tu IP si es posible)"
echo "   - Los puertos públicos de los servicios que expongas"

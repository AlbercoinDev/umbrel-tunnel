#!/bin/sh
set -e

mkdir -p /data/wireguard /etc/wireguard /etc/haproxy /var/run
chmod 700 /data /data/wireguard /etc/wireguard 2>/dev/null || true

# The host kernel usually ships WireGuard. With /lib/modules mounted and
# SYS_MODULE granted, this loads it on first start; a built-in module is fine
# too and modprobe simply returns success.
if command -v modprobe >/dev/null 2>&1; then
  modprobe wireguard 2>/dev/null || true
fi

exec python3 /app/serve.py

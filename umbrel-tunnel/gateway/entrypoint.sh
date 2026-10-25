#!/bin/sh
set -e

mkdir -p /data/config /data/wireguard /etc/wireguard /etc/haproxy
chmod 700 /data /data/config /data/wireguard /etc/wireguard 2>/dev/null || true

exec python3 /app/app.py

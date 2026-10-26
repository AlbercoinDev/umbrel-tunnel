#!/usr/bin/env bash
#
# umbrel-tunnel installer for Debian 12/13 and Ubuntu 22.04/24.04+.
#
# It installs WireGuard, nftables and the umbrel-tunnel control plane, creates the
# server keys, starts the systemd units and prints the pairing code for the
# Umbrel app. It is safe to run again: existing configuration is preserved
# unless --force is used.
#
# Usage:
#   sudo ./install.sh [options]
#   curl -fsSL <url>/install.sh | sudo bash -s -- --binary-base <url>
#
set -Eeuo pipefail

PROGRAM="umbrel-tunnel"
BIN_PATH="/usr/local/bin/umbrel-tunnel"
ETC_DIR="/etc/umbrel-tunnel"
STATE_DIR="/var/lib/umbrel-tunnel"
RUN_DIR="/run/umbrel-tunnel"
WG_DIR="/etc/wireguard"
PAIRING_FILE="/root/umbrel-tunnel-pairing.txt"

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd)"
fi

VERSION="dev"
if [[ -n "$SCRIPT_DIR" && -r "$SCRIPT_DIR/VERSION" ]]; then
  VERSION="$(tr -d ' \n' <"$SCRIPT_DIR/VERSION")"
fi

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BLUE=$'\033[34m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'
else
  C_RESET=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""
fi

log()  { printf '%s==>%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s OK %s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%sWARN%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%sERROR%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

on_error() {
  local code=$?
  printf '%sERROR%s fallo inesperado en la línea %s (código %s)\n' \
    "$C_RED" "$C_RESET" "${1:-?}" "$code" >&2
  printf 'Revisa el log con: journalctl -xe\n' >&2
}
trap 'on_error $LINENO' ERR

# ---------------------------------------------------------------- options ---
ENDPOINT=""
TOKEN=""
API_PORT=8080
WG_PORT=51820
SUBNET=""
SERVER_IP=""
UMBREL_IP=""
MTU=""
UMBREL_PUBKEY=""
BINARY_BASE=""
PUBLIC_API=0
FORCE=0
DRY_RUN=0
ASSUME_YES=0
NO_START=0
UNINSTALL=0
PURGE=0
BINARY=""
ARCH=""
PUBLIC_IP=""
MISSING_PACKAGES=()
FIREWALL_WARNING=0
FAILED=0

usage() {
  cat <<'EOF'
umbrel-tunnel installer

Uso:
  sudo ./install.sh [opciones]
  curl -fsSL <url>/install.sh | sudo bash -s -- --binary-base <url>

Opciones:
  --endpoint IP        IP pública fija del VPS (si se omite se detecta)
  --token TOKEN        token de API (si se omite se genera)
  --api-port PORT      puerto de la API dentro del túnel (por defecto 8080)
  --wg-port PORT       puerto UDP de WireGuard (por defecto 51820)
  --subnet CIDR        subred del túnel (por defecto 10.0.0.0/24)
  --server-ip IP       IP del servidor dentro del túnel (por defecto 10.0.0.1)
  --umbrel-ip IP       IP de Umbrel dentro del túnel (por defecto 10.0.0.2)
  --mtu N              MTU del túnel (por defecto 1420)
  --umbrel-pubkey KEY  clave pública de Umbrel (la genera la app)
  --public-api         expone la API fuera del túnel (no recomendado)
  --binary URL|RUTA    binario a instalar (por defecto, el que acompaña al script)
  --binary-base URL    base de descarga; añade /umbrel-tunnel-linux-$ARCH
  --force              sustituye configuración y wg0.conf existentes
  --no-start           instala pero no arranca los servicios
  --dry-run            muestra lo que haría sin cambiar nada
  --yes                no pregunta (instalación desatendida)
  --uninstall          desinstala umbrel-tunnel
  --purge              con --uninstall, borra también configuración y estado
  --version            muestra la versión
  -h, --help           esta ayuda
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --endpoint) ENDPOINT="${2:-}"; shift 2 ;;
      --endpoint=*) ENDPOINT="${1#*=}"; shift ;;
      --token) TOKEN="${2:-}"; shift 2 ;;
      --token=*) TOKEN="${1#*=}"; shift ;;
      --api-port) API_PORT="${2:-}"; shift 2 ;;
      --api-port=*) API_PORT="${1#*=}"; shift ;;
      --wg-port) WG_PORT="${2:-}"; shift 2 ;;
      --wg-port=*) WG_PORT="${1#*=}"; shift ;;
      --subnet) SUBNET="${2:-}"; shift 2 ;;
      --subnet=*) SUBNET="${1#*=}"; shift ;;
      --server-ip) SERVER_IP="${2:-}"; shift 2 ;;
      --server-ip=*) SERVER_IP="${1#*=}"; shift ;;
      --umbrel-ip) UMBREL_IP="${2:-}"; shift 2 ;;
      --umbrel-ip=*) UMBREL_IP="${1#*=}"; shift ;;
      --mtu) MTU="${2:-}"; shift 2 ;;
      --mtu=*) MTU="${1#*=}"; shift ;;
      --umbrel-pubkey) UMBREL_PUBKEY="${2:-}"; shift 2 ;;
      --umbrel-pubkey=*) UMBREL_PUBKEY="${1#*=}"; shift ;;
      --binary) BINARY="${2:-}"; shift 2 ;;
      --binary=*) BINARY="${1#*=}"; shift ;;
      --binary-base) BINARY_BASE="${2:-}"; shift 2 ;;
      --binary-base=*) BINARY_BASE="${1#*=}"; shift ;;
      --public-api) PUBLIC_API=1; shift ;;
      --force) FORCE=1; shift ;;
      --no-start) NO_START=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --purge) PURGE=1; shift ;;
      --version) echo "$VERSION"; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *) die "opción desconocida: $1 (usa --help)" ;;
    esac
  done

  [[ "$API_PORT" =~ ^[0-9]+$ ]] && ((API_PORT >= 1 && API_PORT <= 65535)) \
    || die "--api-port inválido: $API_PORT"
  [[ "$WG_PORT" =~ ^[0-9]+$ ]] && ((WG_PORT >= 1 && WG_PORT <= 65535)) \
    || die "--wg-port inválido: $WG_PORT"
  if [[ -n "$MTU" ]]; then
    [[ "$MTU" =~ ^[0-9]+$ ]] && ((MTU >= 1280 && MTU <= 1500)) \
      || die "--mtu inválido: $MTU (1280-1500)"
  fi
  if [[ -n "$BINARY" && -n "$BINARY_BASE" ]]; then
    die "usa --binary o --binary-base, no ambos"
  fi
}

# ------------------------------------------------------------------- utils ---
run() {
  if ((DRY_RUN)); then
    printf '%s[dry-run]%s' "$C_YELLOW" "$C_RESET"
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

run_shell() {
  if ((DRY_RUN)); then
    printf '%s[dry-run]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"
    return 0
  fi
  bash -c "$*"
}

write_file() {
  local path=$1 mode=$2
  if ((DRY_RUN)); then
    printf '%s[dry-run]%s escribir %s (%s)\n' "$C_YELLOW" "$C_RESET" "$path" "$mode"
    cat >/dev/null
    return 0
  fi
  install -d -m 0755 "$(dirname -- "$path")"
  cat >"$path"
  chmod "$mode" "$path"
}

have() { command -v "$1" >/dev/null 2>&1; }

version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

# --------------------------------------------------------------- preflight ---
require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "ejecuta como root: sudo $0 $*"
  fi
}

check_os() {
  local os_release="${UMBREL_TUNNEL_OS_RELEASE:-/etc/os-release}"
  [[ -r "$os_release" ]] || die "no se pudo leer $os_release"
  # shellcheck disable=SC1090
  . "$os_release"
  case "${ID:-}" in
    debian)
      version_ge "${VERSION_ID:-0}" "12" || die "se requiere Debian 12 o superior (detectado ${VERSION_ID:-?})"
      ;;
    ubuntu)
      version_ge "${VERSION_ID:-0}" "22.04" || die "se requiere Ubuntu 22.04 o superior (detectado ${VERSION_ID:-?})"
      ;;
    *)
      die "sistema no soportado: ${PRETTY_NAME:-desconocido}. Usa Debian 12/13 o Ubuntu 22.04+"
      ;;
  esac
  ok "sistema: ${PRETTY_NAME:-$ID $VERSION_ID}"
}

check_arch() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "arquitectura no soportada: $(uname -m) (se requiere amd64 o arm64)" ;;
  esac
  ok "arquitectura: $ARCH"
}

check_systemd() {
  [[ -d /run/systemd/system ]] || die "systemd no está activo; este instalador lo requiere"
  ok "systemd activo"
}

check_internet() {
  local url
  if ! have curl; then
    if getent hosts deb.debian.org >/dev/null 2>&1; then
      ok "DNS correcto (curl se instalará con las dependencias)"
      return 0
    fi
    die "sin salida a internet (no hay curl ni resolución DNS)"
  fi
  for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
    if PUBLIC_IP="$(curl -4 -fsS --max-time 8 "$url" 2>/dev/null)"; then
      PUBLIC_IP="$(printf '%s' "$PUBLIC_IP" | tr -d '[:space:]')"
      if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ok "salida a internet correcta (IP pública: $PUBLIC_IP)"
        return 0
      fi
    fi
  done
  die "sin salida a internet o no se pudo detectar la IP pública; usa --endpoint IP"
}

detect_public_ip() {
  [[ -n "$PUBLIC_IP" || -n "$ENDPOINT" ]] && return 0
  have curl || return 0
  local url
  for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
    if PUBLIC_IP="$(curl -4 -fsS --max-time 8 "$url" 2>/dev/null)"; then
      PUBLIC_IP="$(printf '%s' "$PUBLIC_IP" | tr -d '[:space:]')"
      if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
      fi
    fi
  done
  PUBLIC_IP=""
}

check_resources() {
  local mem_kb avail_kb
  mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  avail_kb="$(df -Pk / | awk 'NR==2 {print $4}')"
  ((mem_kb >= 131072)) || warn "RAM total baja (${mem_kb} kB); se recomiendan 128 MB o más"
  ((avail_kb >= 150000)) || die "espacio libre insuficiente en / (${avail_kb} kB); se necesitan ~150 MB"
  ok "recursos: $((mem_kb / 1024)) MB RAM, $((avail_kb / 1024)) MB libres"
}

check_tun() {
  if [[ ! -c /dev/net/tun ]]; then
    if ((DRY_RUN)); then
      warn "/dev/net/tun no existe (se intentará cargar el módulo tun)"
    else
      modprobe tun 2>/dev/null || true
    fi
  fi
  if [[ -c /dev/net/tun ]]; then
    ok "/dev/net/tun disponible"
  else
    warn "/dev/net/tun no disponible; WireGuard puede funcionar igualmente, pero revisa el kernel"
  fi
}

check_wireguard_module() {
  if ((DRY_RUN)); then
    ok "comprobación del módulo wireguard omitida (dry-run)"
    return 0
  fi
  if modprobe wireguard 2>/dev/null && [[ -d /sys/module/wireguard ]]; then
    ok "módulo wireguard cargado"
  else
    warn "el módulo wireguard aún no está cargado; se instalará el paquete correspondiente"
  fi
}

check_packages() {
  local pkg status
  for pkg in wireguard wireguard-tools nftables curl ca-certificates iproute2 kmod; do
    status="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"
    if [[ "$status" != *"install ok installed"* ]]; then
      MISSING_PACKAGES+=("$pkg")
    fi
  done
  if ((${#MISSING_PACKAGES[@]} == 0)); then
    ok "dependencias del sistema ya instaladas"
  else
    log "paquetes que faltan: ${MISSING_PACKAGES[*]}"
  fi
}

check_port() {
  local proto=$1 port=$2 label=$3
  local flag="-l${proto}n"
  if ! have ss; then
    return 0
  fi
  if ss -H "$flag" "sport = :$port" 2>/dev/null | grep -q .; then
    if [[ "$port" == "$API_PORT" ]] && systemctl is-active --quiet umbrel-tunnel 2>/dev/null; then
      ok "puerto $port/$proto en uso por umbrel-tunnel (reinstalación)"
      return 0
    fi
    if [[ "$port" == "$WG_PORT" ]] && wg show wg0 >/dev/null 2>&1; then
      ok "puerto $port/$proto en uso por wg0 (reinstalación)"
      return 0
    fi
    die "el puerto $port/$proto ($label) ya está en uso; cambia --api-port/--wg-port"
  fi
  ok "puerto $port/$proto libre"
}

check_ports() {
  check_port t "$API_PORT" "API"
  check_port u "$WG_PORT" "WireGuard"
}

check_existing_wg() {
  local file="$WG_DIR/wg0.conf"
  if [[ -f "$file" ]] && ! grep -q "Managed by umbrel-tunnel" "$file"; then
    if ((FORCE)); then
      local backup="$file.bak.$(date +%Y%m%d%H%M%S)"
      run cp -a "$file" "$backup"
      warn "wg0.conf existente respaldado en $backup"
    else
      die "existe $file y no lo gestiona umbrel-tunnel; usa --force para respaldarlo y sustituirlo"
    fi
  fi
}

check_firewall_manager() {
  if have ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
    FIREWALL_WARNING=1
    warn "ufw está activo. Los puertos públicos necesitan reglas 'route' además de nftables:"
    warn "  ufw route allow proto tcp to 10.0.0.2 port <puerto>"
    warn "  ufw allow $WG_PORT/udp"
  fi
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    FIREWALL_WARNING=1
    warn "firewalld está activo; añade el puerto $WG_PORT/udp y el tráfico enrutado hacia wg0"
  fi
}

preflight() {
  log "comprobaciones previas"
  require_root "$@"
  check_os
  check_arch
  check_systemd
  check_internet
  check_resources
  check_tun
  check_wireguard_module
  check_packages
  check_ports
  check_existing_wg
  check_firewall_manager
}
# ---------------------------------------------------------------- install ---
install_packages() {
  if ((${#MISSING_PACKAGES[@]} == 0)); then
    return 0
  fi
  log "instalando paquetes: ${MISSING_PACKAGES[*]}"
  run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${MISSING_PACKAGES[@]}"
  if ((!DRY_RUN)); then
    have wg && have wg-quick && have nft || die "los paquetes se instalaron pero faltan wg/wg-quick/nft"
    ok "dependencias instaladas"
  fi
}

resolve_binary() {
  if [[ -z "$BINARY" && -n "$BINARY_BASE" ]]; then
    BINARY="${BINARY_BASE%/}/$PROGRAM-linux-$ARCH"
    log "descarga desde la base indicada: $BINARY"
  fi
  if [[ -n "$BINARY" ]]; then
    if [[ "$BINARY" =~ ^https?:// ]]; then
      if ((DRY_RUN)); then
        BIN_SOURCE="(descarga de $BINARY)"
        return 0
      fi
      local tmp
      tmp="$(mktemp)"
      log "descargando binario"
      curl -fsSL --retry 2 --max-time 120 "$BINARY" -o "$tmp" || die "no se pudo descargar $BINARY"
      BIN_SOURCE="$tmp"
    else
      BIN_SOURCE="$BINARY"
    fi
  elif [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/$PROGRAM" ]]; then
    BIN_SOURCE="$SCRIPT_DIR/$PROGRAM"
  elif [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/dist/$PROGRAM-linux-$ARCH" ]]; then
    BIN_SOURCE="$SCRIPT_DIR/dist/$PROGRAM-linux-$ARCH"
  elif [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/../dist/$PROGRAM-linux-$ARCH" ]]; then
    BIN_SOURCE="$SCRIPT_DIR/../dist/$PROGRAM-linux-$ARCH"
  elif [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/$PROGRAM-linux-$ARCH" ]]; then
    BIN_SOURCE="$SCRIPT_DIR/$PROGRAM-linux-$ARCH"
  else
    die "no encuentro el binario. Usa --binary URL|RUTA o coloca $PROGRAM junto al script"
  fi
  if [[ "$BIN_SOURCE" != "(descarga"* && ! -f "$BIN_SOURCE" ]]; then
    die "el binario no existe: $BIN_SOURCE"
  fi
  ok "binario: $BIN_SOURCE"
}

install_binary() {
  log "instalando binario en $BIN_PATH"
  run install -d -m 0755 /usr/local/bin
  run install -m 0755 "$BIN_SOURCE" "/usr/local/bin/.$PROGRAM.new"
  run mv -f "/usr/local/bin/.$PROGRAM.new" "$BIN_PATH"
  if ((!DRY_RUN)); then
    "$BIN_PATH" version >/dev/null || die "el binario instalado no se ejecuta"
    ok "binario $("$BIN_PATH" version) instalado"
  fi
}

install_units() {
  log "instalando unidades systemd"
  if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/packaging/umbrel-tunnel.service" ]]; then
    run install -m 0644 "$SCRIPT_DIR/packaging/umbrel-tunnel.service" /etc/systemd/system/umbrel-tunnel.service
    run install -m 0644 "$SCRIPT_DIR/packaging/umbrel-tunnel-firewall.service" /etc/systemd/system/umbrel-tunnel-firewall.service
    run install -m 0644 "$SCRIPT_DIR/packaging/umbrel-tunnel.conf" /etc/tmpfiles.d/umbrel-tunnel.conf
    run install -m 0644 "$SCRIPT_DIR/packaging/90-umbrel-tunnel.conf" /etc/sysctl.d/90-umbrel-tunnel.conf
    return 0
  fi

  # Fallback for `curl | bash` installs. Keep in sync with packaging/.
  write_file /etc/systemd/system/umbrel-tunnel.service 0644 <<'EOF'
[Unit]
Description=umbrel-tunnel control plane
After=network-online.target wg-quick@wg0.service umbrel-tunnel-firewall.service
Wants=network-online.target
Requires=wg-quick@wg0.service umbrel-tunnel-firewall.service

[Service]
Type=simple
ExecStart=/usr/local/bin/umbrel-tunnel serve
Restart=on-failure
RestartSec=3s
TimeoutStopSec=10s
User=root
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
ReadWritePaths=/etc/umbrel-tunnel /var/lib/umbrel-tunnel /run/umbrel-tunnel /etc/wireguard
MemoryHigh=48M
MemoryMax=96M
TasksMax=64
LimitNOFILE=1024

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/umbrel-tunnel-firewall.service 0644 <<'EOF'
[Unit]
Description=umbrel-tunnel nftables firewall
After=network-pre.target wg-quick@wg0.service
Wants=wg-quick@wg0.service
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet umbrel_tunnel
ExecStart=/usr/sbin/nft -f /etc/umbrel-tunnel/rules.nft
ExecReload=-/usr/sbin/nft delete table inet umbrel_tunnel
ExecReload=/usr/sbin/nft -f /etc/umbrel-tunnel/rules.nft
ExecStop=-/usr/sbin/nft delete table inet umbrel_tunnel
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ReadOnlyPaths=/etc/umbrel-tunnel
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/tmpfiles.d/umbrel-tunnel.conf 0644 <<'EOF'
d /etc/umbrel-tunnel 0700 root root -
d /var/lib/umbrel-tunnel 0700 root root -
d /run/umbrel-tunnel 0755 root root -
EOF

  write_file /etc/sysctl.d/90-umbrel-tunnel.conf 0644 <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.src_valid_mark = 1
EOF
}

init_config() {
  log "creando configuración y claves"
  if [[ -f "$ETC_DIR/config.json" ]] && ((!FORCE)); then
    ok "configuración existente conservada ($ETC_DIR/config.json)"
    return 0
  fi
  local args=(init)
  [[ -n "$ENDPOINT" ]] && args+=(--endpoint "$ENDPOINT")
  [[ -n "$TOKEN" ]] && args+=(--token "$TOKEN")
  [[ -n "$SUBNET" ]] && args+=(--subnet "$SUBNET")
  [[ -n "$SERVER_IP" ]] && args+=(--server-ip "$SERVER_IP")
  [[ -n "$UMBREL_IP" ]] && args+=(--umbrel-ip "$UMBREL_IP")
  [[ -n "$MTU" ]] && args+=(--mtu "$MTU")
  [[ -n "$UMBREL_PUBKEY" ]] && args+=(--umbrel-pubkey "$UMBREL_PUBKEY")
  args+=(--api-port "$API_PORT" --wg-port "$WG_PORT")
  ((PUBLIC_API)) && args+=(--public-api)
  ((FORCE)) && args+=(--force)
  run "$BIN_PATH" "${args[@]}"
  ok "configuración creada"
}

enable_services() {
  log "activando servicios"
  run systemctl daemon-reload
  run systemd-tmpfiles --create /etc/tmpfiles.d/umbrel-tunnel.conf
  if ((DRY_RUN)); then
    run sysctl --system
  else
    sysctl --system >/dev/null
  fi
  run systemctl enable wg-quick@wg0.service umbrel-tunnel-firewall.service umbrel-tunnel.service
  if ((NO_START)); then
    warn "servicios no arrancados (--no-start)"
    return 0
  fi
  run systemctl restart wg-quick@wg0.service
  run systemctl restart umbrel-tunnel-firewall.service
  run systemctl restart umbrel-tunnel.service
}

# --------------------------------------------------------------- post-check ---
check_service() {
  local unit=$1
  if systemctl is-active --quiet "$unit"; then
    ok "$unit activo"
  else
    warn "$unit no está activo"
    FAILED=1
  fi
}

postflight() {
  if ((DRY_RUN)); then
    return 0
  fi
  log "verificando instalación"
  sleep 1

  local i healthy=0
  for i in $(seq 1 15); do
    if curl -fsS --max-time 2 "http://10.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
      healthy=1
      break
    fi
    sleep 1
  done
  if ((healthy)); then
    ok "API responde en 10.0.0.1:${API_PORT}"
  else
    warn "la API no responde en 10.0.0.1:${API_PORT}"
    FAILED=1
    journalctl -u umbrel-tunnel -n 20 --no-pager 2>/dev/null || true
  fi

  check_service wg-quick@wg0.service
  check_service umbrel-tunnel-firewall.service
  check_service umbrel-tunnel.service

  if nft list table inet umbrel_tunnel >/dev/null 2>&1; then
    ok "tabla nftables inet umbrel_tunnel presente"
  else
    warn "falta la tabla nftables inet umbrel_tunnel"
    FAILED=1
  fi

  local bind
  bind="$(ss -H -ltn "sport = :$API_PORT" 2>/dev/null | awk '{print $4}' | head -n1 || true)"
  if ((PUBLIC_API)); then
    warn "API pública activada (--public-api): $bind"
  elif [[ "$bind" == "10.0.0.1:$API_PORT" ]]; then
    ok "API escucha solo en el túnel ($bind)"
  else
    warn "la API no escucha en 10.0.0.1:$API_PORT (encontrado: ${bind:-nada})"
    FAILED=1
  fi

  local pid rss
  pid="$(systemctl show -p MainPID --value umbrel-tunnel 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && ((pid > 0)) && [[ -r "/proc/$pid/status" ]]; then
    rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")"
    ok "RAM del servicio: $((rss / 1024)) MiB"
    if ((rss > 40960)); then
      warn "consumo de RAM alto ($((rss / 1024)) MiB); revisa peers y logs"
    fi
  fi

  ok "disco usado: $(du -sh "$BIN_PATH" "$ETC_DIR" "$STATE_DIR" 2>/dev/null | awk '{print $1}' | paste -sd ' ' -)"
}

print_pairing() {
  if ((DRY_RUN)); then
    return 0
  fi
  if ! "$BIN_PATH" pair >"$PAIRING_FILE" 2>/dev/null; then
    warn "no se pudo generar el código de emparejamiento"
    return 0
  fi
  chmod 0600 "$PAIRING_FILE"
  printf '\n%s================ EMPAREJAMIENTO ================%s\n' "$C_BOLD" "$C_RESET"
  cat "$PAIRING_FILE"
  printf '%s================================================%s\n' "$C_BOLD" "$C_RESET"
  log "pega el bloque completo en la app de Umbrel (pestaña Conexión)"
  log "guardado en $PAIRING_FILE (solo root)"
}

print_summary() {
  local endpoint="$ENDPOINT"
  local server_ip="${SERVER_IP:-10.0.0.1}"
  if [[ -z "$endpoint" ]]; then
    endpoint="$PUBLIC_IP"
  fi
  printf '\n%sInstalación completada%s\n' "$C_GREEN$C_BOLD" "$C_RESET"
  printf '  Versión:      %s\n' "$VERSION"
  printf '  Endpoint:     %s:%s/udp\n' "${endpoint:-?}" "$WG_PORT"
  printf '  API (túnel):  http://%s:%s\n' "$server_ip" "$API_PORT"
  printf '  Panel VPS:    http://%s:%s (desde el túnel)\n' "$server_ip" "$API_PORT"
  if [[ -n "$UMBREL_PUBKEY" ]]; then
    printf '\nVuelve a la app de Umbrel y pega el bloque de emparejamiento.\n'
  else
    printf '\nSiguiente paso: instala la app de Umbrel y pega el código ut1.\n'
  fi
  if ((FIREWALL_WARNING)); then
    printf '\n%sAviso:%s hay un firewall del sistema activo. Abre %s/udp y el tráfico\n' \
      "$C_YELLOW" "$C_RESET" "$WG_PORT"
    printf 'enrutado hacia wg0 (ver mensajes anteriores).\n'
  fi
  if ((FAILED)); then
    printf '\n%sAlgunas comprobaciones fallaron.%s Revisa:\n' "$C_RED" "$C_RESET"
    printf '  systemctl status umbrel-tunnel umbrel-tunnel-firewall wg-quick@wg0\n'
    printf '  journalctl -u umbrel-tunnel -n 50 --no-pager\n'
    exit 1
  fi
}

# --------------------------------------------------------------- uninstall ---
do_uninstall() {
  require_root "$@"
  log "desinstalando umbrel-tunnel"
  run_shell "systemctl disable --now umbrel-tunnel.service umbrel-tunnel-firewall.service wg-quick@wg0.service 2>/dev/null || true"
  run_shell "nft delete table inet umbrel_tunnel 2>/dev/null || true"
  run rm -f /etc/systemd/system/umbrel-tunnel.service \
    /etc/systemd/system/umbrel-tunnel-firewall.service \
    /etc/tmpfiles.d/umbrel-tunnel.conf \
    /etc/sysctl.d/90-umbrel-tunnel.conf
  run systemctl daemon-reload
  if [[ -f "$WG_DIR/wg0.conf" ]] && grep -q "Managed by umbrel-tunnel" "$WG_DIR/wg0.conf"; then
    run rm -f "$WG_DIR/wg0.conf"
  fi
  run rm -f "$BIN_PATH" "$PAIRING_FILE"
  if ((PURGE)); then
    run rm -rf "$ETC_DIR" "$STATE_DIR" "$RUN_DIR"
    ok "configuración y estado eliminados"
  else
    log "se conservaron $ETC_DIR y $STATE_DIR (usa --purge para borrarlos)"
  fi
  ok "desinstalación completada"
}

# -------------------------------------------------------------------- main ---
main() {
  parse_args "$@"

  if ((UNINSTALL)); then
    do_uninstall "$@"
    return 0
  fi

  preflight "$@"
  install_packages
  detect_public_ip
  check_wireguard_module
  resolve_binary
  install_binary
  install_units
  init_config
  enable_services
  postflight
  print_pairing
  print_summary
}

main "$@"

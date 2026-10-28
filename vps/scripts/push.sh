#!/usr/bin/env bash
#
# Build the umbrel-tunnel release, copy it to a VPS over SSH and run the installer.
#
# Usage:
#   ./scripts/push.sh root@203.0.113.10 [options]
#
# The remote user must be root or have sudo. If sudo asks for a password, the
# SSH session allocates a TTY so you can type it.
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
VERSION="$(tr -d ' \n' <"$ROOT_DIR/VERSION")"

HOST=""
SSH_PORT=22
SSH_KEY=""
ARCH="auto"
ENDPOINT=""
TOKEN=""
API_PORT=""
WG_PORT=""
SUBNET=""
UMBREL_PUBKEY=""
PUBLIC_API=0
FORCE=0
DRY_RUN=0
NO_START=0
PURGE=0
NO_BUILD=0

usage() {
  cat <<'EOF'
Uso: ./scripts/push.sh usuario@vps [opciones]

Opciones:
  --endpoint IP        IP pública fija del VPS (si se omite, se detecta allí)
  --token TOKEN        token generado por la app (debe coincidir con el bootstrap)
  --api-port PORT      puerto de la API dentro del túnel
  --wg-port PORT       puerto UDP de WireGuard
  --subnet CIDR        subred del túnel
  --umbrel-pubkey KEY  emparejamiento manual con esta clave pública
  --public-api         expone la API fuera del túnel (no recomendado)
  --arch ARCH          amd64, arm64 o auto (por defecto auto)
  --ssh-port PORT      puerto SSH (por defecto 22)
  --ssh-key FILE       clave privada SSH
  --force              sustituye configuración existente en el VPS
  --no-start           instala sin arrancar los servicios
  --dry-run            pasa --dry-run al instalador remoto
  --purge              desinstala y borra configuración y estado
  --no-build           usa el tarball ya presente en dist/
  -h, --help           esta ayuda
EOF
}

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*" >&2; }
die()  { printf 'ERROR %s\n' "$*" >&2; exit 1; }

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
      --umbrel-pubkey) UMBREL_PUBKEY="${2:-}"; shift 2 ;;
      --umbrel-pubkey=*) UMBREL_PUBKEY="${1#*=}"; shift ;;
      --arch) ARCH="${2:-}"; shift 2 ;;
      --arch=*) ARCH="${1#*=}"; shift ;;
      --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
      --ssh-port=*) SSH_PORT="${1#*=}"; shift ;;
      --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
      --ssh-key=*) SSH_KEY="${1#*=}"; shift ;;
      --public-api) PUBLIC_API=1; shift ;;
      --force) FORCE=1; shift ;;
      --no-start) NO_START=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --purge) PURGE=1; shift ;;
      --no-build) NO_BUILD=1; shift ;;
      -h|--help) usage; exit 0 ;;
      -*) die "opción desconocida: $1" ;;
      *)
        [[ -z "$HOST" ]] || die "sobra el argumento: $1"
        HOST="$1"
        shift
        ;;
    esac
  done

  [[ -n "$HOST" ]] || { usage; die "falta usuario@vps"; }
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port inválido"
  [[ "$ARCH" == "auto" || "$ARCH" == "amd64" || "$ARCH" == "arm64" ]] || die "--arch inválido"
  if [[ -n "$ENDPOINT" && ! "$ENDPOINT" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    die "--endpoint debe ser una IPv4 (sin nombre ni puerto)"
  fi
}

SSH_OPTS=()
SSH_TTY_OPTS=()
build_ssh_opts() {
  SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$SSH_PORT")
  # The installer may need to prompt for sudo (or an SSH password), so the
  # interactive session must not use BatchMode.
  SSH_TTY_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$SSH_PORT")
  if [[ -n "$SSH_KEY" ]]; then
    SSH_OPTS+=(-i "$SSH_KEY")
    SSH_TTY_OPTS+=(-i "$SSH_KEY")
  fi
}

remote() {
  ssh "${SSH_OPTS[@]}" "$HOST" "$@"
}

detect_arch() {
  local machine
  machine="$(remote 'uname -m' 2>/dev/null)" || die "no se pudo conectar por SSH a $HOST"
  case "$machine" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "arquitectura remota no soportada: $machine" ;;
  esac
}

build_dist() {
  if ((NO_BUILD)); then
    log "usando el tarball existente (--no-build)"
    return 0
  fi
  log "compilando versión $VERSION"
  make -C "$ROOT_DIR" dist >/dev/null
}

installer_args() {
  local args=()
  [[ -n "$ENDPOINT" ]] && args+=(--endpoint "$ENDPOINT")
  [[ -n "$TOKEN" ]] && args+=(--token "$TOKEN")
  [[ -n "$API_PORT" ]] && args+=(--api-port "$API_PORT")
  [[ -n "$WG_PORT" ]] && args+=(--wg-port "$WG_PORT")
  [[ -n "$SUBNET" ]] && args+=(--subnet "$SUBNET")
  [[ -n "$UMBREL_PUBKEY" ]] && args+=(--umbrel-pubkey "$UMBREL_PUBKEY")
  ((PUBLIC_API)) && args+=(--public-api)
  ((FORCE)) && args+=(--force)
  ((DRY_RUN)) && args+=(--dry-run)
  ((NO_START)) && args+=(--no-start)
  # Preserve each argument (including secrets containing spaces or shell chars)
  # across SSH without evaluating an installer command string remotely.
  if ((${#args[@]})); then printf '%s\0' "${args[@]}"; fi
}

main() {
  parse_args "$@"
  build_ssh_opts

  log "comprobando conexión con $HOST"
  if [[ "$ARCH" == "auto" ]]; then
    ARCH="$(detect_arch)"
  fi
  log "arquitectura remota: $ARCH"

  if ((PURGE)); then
    DRY_RUN=0
    log "modo desinstalación (--purge)"
  fi

  build_dist

  local tarball="$ROOT_DIR/dist/umbrel-tunnel-${VERSION}-linux-${ARCH}.tar.gz"
  [[ -f "$tarball" ]] || die "no existe $tarball"
  local remote_tar="/tmp/$(basename "$tarball")"

  log "copiando $(basename "$tarball")"
  local scp_opts=(-q -P "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
  if [[ -n "$SSH_KEY" ]]; then
    scp_opts+=(-i "$SSH_KEY")
  fi
  scp "${scp_opts[@]}" "$tarball" "$HOST:$remote_tar"

  local args
  if ((PURGE)); then
    args="$(printf '%s\0' --uninstall --purge | base64 -w0)"
  else
    args="$(installer_args | base64 -w0)"
  fi

  log "instalando en $HOST (puede pedir la contraseña de sudo)"
  ssh -t "${SSH_TTY_OPTS[@]}" "$HOST" \
    "TARBALL=$(printf '%q' "$remote_tar") INSTALL_ARGS_B64=$(printf '%q' "$args") bash -s" <<'REMOTE'
set -Eeuo pipefail
mapfile -d '' -t install_args < <(printf '%s' "$INSTALL_ARGS_B64" | base64 -d)
dir="$(mktemp -d)"
cleanup() { rm -rf "$dir"; }
trap cleanup EXIT
tar -xzf "$TARBALL" -C "$dir"
cd "$dir"/umbrel-tunnel-*
if [[ "$(id -u)" -eq 0 ]]; then
  ./install.sh "${install_args[@]}"
else
  sudo ./install.sh "${install_args[@]}"
fi
REMOTE

  remote "rm -f $(printf '%q' "$remote_tar")" 2>/dev/null || true
  log "hecho. El código de emparejamiento aparece arriba y queda en /root/umbrel-tunnel-pairing.txt del VPS."
}

main "$@"

"""Gestión de WireGuard dentro del contenedor del gateway."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

DATA_WG_DIR = Path("/data/wireguard")
DATA_CONF = DATA_WG_DIR / "wg0.conf"
ETC_CONF = Path("/etc/wireguard/wg0.conf")
INTERFACE = "wg0"


class WireGuardError(RuntimeError):
    pass


def _run(args: list[str], input_data: str | None = None) -> str:
    try:
        result = subprocess.run(
            args,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WireGuardError(f"no se pudo ejecutar {' '.join(args)}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise WireGuardError(detail or f"{' '.join(args)} falló")
    return result.stdout


def validate_config(text: str) -> None:
    if "[Interface]" not in text or "[Peer]" not in text:
        raise WireGuardError("la configuración debe tener [Interface] y [Peer]")
    if not re.search(r"^\s*PrivateKey\s*=\s*\S+", text, re.MULTILINE):
        raise WireGuardError("falta PrivateKey en [Interface]")
    if not re.search(r"^\s*PublicKey\s*=\s*\S+", text, re.MULTILINE):
        raise WireGuardError("falta PublicKey en [Peer]")
    if not re.search(r"^\s*Endpoint\s*=\s*\S+", text, re.MULTILINE):
        raise WireGuardError("falta Endpoint en [Peer]")


def save_config(text: str) -> None:
    validate_config(text)
    DATA_WG_DIR.mkdir(parents=True, exist_ok=True)
    ETC_CONF.parent.mkdir(parents=True, exist_ok=True)
    DATA_CONF.write_text(text.rstrip() + "\n", encoding="utf-8")
    DATA_CONF.chmod(0o600)
    ETC_CONF.write_text(text.rstrip() + "\n", encoding="utf-8")
    ETC_CONF.chmod(0o600)


def config_text() -> str:
    try:
        return DATA_CONF.read_text(encoding="utf-8")
    except OSError:
        return ""


def apply_saved() -> tuple[bool, str]:
    text = config_text()
    if not text:
        return False, "no hay configuración de WireGuard"
    ETC_CONF.parent.mkdir(parents=True, exist_ok=True)
    ETC_CONF.write_text(text, encoding="utf-8")
    ETC_CONF.chmod(0o600)
    try:
        subprocess.run(["wg-quick", "down", INTERFACE], capture_output=True, text=True, timeout=15)
        _run(["wg-quick", "up", INTERFACE])
        return True, "WireGuard activo"
    except WireGuardError as exc:
        return False, str(exc)


def remove() -> None:
    subprocess.run(["wg-quick", "down", INTERFACE], capture_output=True, text=True, timeout=15)
    for path in (DATA_CONF, ETC_CONF):
        try:
            path.unlink()
        except OSError:
            pass


def address() -> str | None:
    """IP local del túnel (10.0.0.2), leída de la configuración."""
    match = re.search(r"^\s*Address\s*=\s*([0-9.]+)", config_text(), re.MULTILINE)
    return match.group(1) if match else None


def generate_keypair() -> tuple[str, str]:
    private = _run(["wg", "genkey"]).strip()
    public = _run(["wg", "pubkey"], input_data=private + "\n").strip()
    if not private or not public:
        raise WireGuardError("wg genkey/pubkey devolvió una clave vacía")
    return private, public


def build_config(
    private_key: str,
    client_ip: str,
    server_public_key: str,
    endpoint: str,
    allowed_ips: str = "10.0.0.0/24",
    mtu: int = 1420,
) -> str:
    host, _, port = endpoint.rpartition(":")
    if not host or not port.isdigit():
        raise WireGuardError("el endpoint debe tener formato IP:puerto")
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {client_ip}/24\n"
        f"MTU = {mtu}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {host}:{port}\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )


def status() -> dict:
    try:
        dump = _run(["wg", "show", INTERFACE, "dump"])
    except WireGuardError as exc:
        return {"running": False, "error": str(exc), "connected": False}
    lines = [line for line in dump.strip().splitlines() if line]
    if not lines:
        return {"running": True, "connected": False}
    interface = lines[0].split("\t")
    peers = []
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        handshake = int(parts[4] or 0)
        peers.append(
            {
                "public_key": parts[0],
                "endpoint": parts[2],
                "allowed_ips": parts[3],
                "latest_handshake": handshake,
                "rx": int(parts[5] or 0),
                "tx": int(parts[6] or 0),
            }
        )
    try:
        addr = _run(["ip", "-4", "addr", "show", INTERFACE])
    except WireGuardError:
        addr = ""
    match = re.search(r"inet\s+([0-9.]+)", addr)
    return {
        "running": True,
        "interface": INTERFACE,
        "public_key": interface[1] if len(interface) > 1 else "",
        "listen_port": int(interface[2]) if len(interface) > 2 and interface[2].isdigit() else 0,
        "address": match.group(1) if match else address(),
        "connected": any(p["latest_handshake"] > 0 for p in peers),
        "peers": peers,
    }

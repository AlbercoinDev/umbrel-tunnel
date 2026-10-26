"""Gestión de WireGuard dentro del contenedor del gateway.

The configuration is generated from structured fields. Arbitrary ``wg-quick``
directives are rejected, especially the hook directives (``PostUp``,
``PreDown``, ``SaveConfig``...) that would execute commands as root.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import subprocess
from pathlib import Path

DATA_DIR = Path(os.environ.get("UMBREL_TUNNEL_DATA", "/data"))
DATA_WG_DIR = DATA_DIR / "wireguard"
DATA_CONF = DATA_WG_DIR / "wg0.conf"
DATA_KEY = DATA_WG_DIR / "private.key"
ETC_CONF = Path(os.environ.get("UMBREL_TUNNEL_WG_CONF", "/etc/wireguard/wg0.conf"))
INTERFACE = "wg0"

ALLOWED_INTERFACE = {"PrivateKey", "Address", "MTU"}
ALLOWED_PEER = {"PublicKey", "Endpoint", "AllowedIPs", "PersistentKeepalive", "PresharedKey"}
ENDPOINT_RE = re.compile(
    r"^(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):(\d{1,5})$"
)


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


def valid_key(value: str) -> bool:
    value = (value or "").strip()
    if len(value) != 44 or not value.endswith("="):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, binascii.Error):
        return False


def validate_subnet(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise WireGuardError(f"subred inválida: {value!r}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise WireGuardError("solo se admite IPv4 en el túnel")
    if network.prefixlen < 8 or network.prefixlen > 30:
        raise WireGuardError("la subred del túnel debe tener un prefijo entre /8 y /30")
    return network


def validate_address(value: str, subnet: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise WireGuardError(f"IP del túnel inválida: {value!r}") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise WireGuardError("solo se admite IPv4 en el túnel")
    network = validate_subnet(subnet)
    if address not in network:
        raise WireGuardError(f"la IP {address} no pertenece a {network}")
    if address in {network.network_address, network.broadcast_address}:
        raise WireGuardError("la IP del túnel no puede ser la dirección de red o broadcast")
    return address


def validate_endpoint(value: str) -> tuple[str, int]:
    match = ENDPOINT_RE.match((value or "").strip())
    if not match:
        raise WireGuardError("el endpoint debe tener formato host:puerto")
    port = int(match.group(1))
    if not (1 <= port <= 65535):
        raise WireGuardError("el puerto del endpoint está fuera de rango")
    return value.strip(), port


def overlaps_network(subnet: str, network_ip: str) -> bool:
    """Return True if the tunnel subnet overlaps Umbrel's Docker network."""
    network_ip = (network_ip or "").strip()
    if not network_ip:
        return False
    try:
        if "/" in network_ip:
            umbrel = ipaddress.ip_network(network_ip, strict=False)
        else:
            umbrel = ipaddress.ip_network(f"{network_ip}/16", strict=False)
    except ValueError:
        return False
    return validate_subnet(subnet).overlaps(umbrel)


def parse_config(text: str) -> tuple[dict[str, str], dict[str, str]]:
    interface: dict[str, str] = {}
    peer: dict[str, str] = {}
    section = ""
    seen_peer = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            if name == "interface" and not interface:
                section = "interface"
            elif name == "peer" and not seen_peer:
                section = "peer"
                seen_peer = True
            else:
                raise WireGuardError(f"sección no permitida o duplicada: {line}")
            continue
        if "=" not in line:
            raise WireGuardError(f"línea inválida: {line!r}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if section == "interface":
            if key not in ALLOWED_INTERFACE:
                raise WireGuardError(f"directiva no permitida en [Interface]: {key}")
            if key in interface:
                raise WireGuardError(f"directiva duplicada: {key}")
            interface[key] = value
        elif section == "peer":
            if key not in ALLOWED_PEER:
                raise WireGuardError(f"directiva no permitida en [Peer]: {key}")
            if key in peer:
                raise WireGuardError(f"directiva duplicada: {key}")
            peer[key] = value
        else:
            raise WireGuardError("directiva fuera de una sección")
    return interface, peer


def validate_config(text: str) -> None:
    interface, peer = parse_config(text)
    if not interface or not peer:
        raise WireGuardError("la configuración debe tener [Interface] y [Peer]")
    if not valid_key(interface.get("PrivateKey", "")):
        raise WireGuardError("PrivateKey inválida")
    if not valid_key(peer.get("PublicKey", "")):
        raise WireGuardError("PublicKey inválida")
    validate_endpoint(peer.get("Endpoint", ""))
    address = interface.get("Address", "")
    if "/" not in address:
        raise WireGuardError("Address debe incluir el prefijo de red")
    try:
        ipaddress.ip_interface(address)
    except ValueError as exc:
        raise WireGuardError("Address inválida") from exc
    allowed = [item.strip() for item in peer.get("AllowedIPs", "").split(",") if item.strip()]
    if not allowed:
        raise WireGuardError("falta AllowedIPs")
    for item in allowed:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise WireGuardError(f"AllowedIPs inválida: {item}") from exc
    if "MTU" in interface:
        try:
            mtu = int(interface["MTU"])
        except ValueError as exc:
            raise WireGuardError("MTU inválida") from exc
        if not (1280 <= mtu <= 1500):
            raise WireGuardError("MTU fuera de rango")
    if "PersistentKeepalive" in peer:
        try:
            keepalive = int(peer["PersistentKeepalive"])
        except ValueError as exc:
            raise WireGuardError("PersistentKeepalive inválido") from exc
        if not (0 <= keepalive <= 65535):
            raise WireGuardError("PersistentKeepalive fuera de rango")
    if "PresharedKey" in peer and not valid_key(peer["PresharedKey"]):
        raise WireGuardError("PresharedKey inválida")


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


def redacted_config() -> str:
    lines = []
    for line in config_text().splitlines():
        if line.strip().startswith(("PrivateKey", "PresharedKey")):
            key = line.split("=", 1)[0].rstrip()
            lines.append(f"{key} = <redacted>")
        else:
            lines.append(line)
    return "\n".join(lines).strip()


def apply_saved() -> tuple[bool, str]:
    text = config_text()
    if not text:
        return False, "no hay configuración de WireGuard"
    validate_config(text)
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
    match = re.search(r"^\s*Address\s*=\s*([0-9.]+)", config_text(), re.MULTILINE)
    return match.group(1) if match else None


def subnet() -> str | None:
    match = re.search(r"^\s*AllowedIPs\s*=\s*([0-9./]+)", config_text(), re.MULTILINE)
    return match.group(1) if match else None


def private_key() -> str:
    try:
        value = DATA_KEY.read_text(encoding="ascii").strip()
        if valid_key(value):
            return value
    except OSError:
        pass
    match = re.search(r"^\s*PrivateKey\s*=\s*(\S+)", config_text(), re.MULTILINE)
    if match and valid_key(match.group(1)):
        return match.group(1)
    return ""


def generate_keypair() -> tuple[str, str]:
    private = _run(["wg", "genkey"]).strip()
    public = _run(["wg", "pubkey"], input_data=private + "\n").strip()
    if not valid_key(private) or not valid_key(public):
        raise WireGuardError("wg genkey/pubkey devolvió una clave vacía")
    return private, public


def save_private_key(private: str) -> None:
    if not valid_key(private):
        raise WireGuardError("clave privada inválida")
    DATA_WG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_KEY.write_text(private + "\n", encoding="ascii")
    DATA_KEY.chmod(0o600)


def ensure_keypair() -> tuple[str, str]:
    """Return the persistent keypair, generating it on first use."""
    private = private_key()
    if not private:
        private, _ = generate_keypair()
        save_private_key(private)
    public = _run(["wg", "pubkey"], input_data=private + "\n").strip()
    if not valid_key(public):
        raise WireGuardError("no se pudo derivar la clave pública")
    return private, public


def public_key() -> str:
    private = private_key()
    if not private:
        return ""
    try:
        return _run(["wg", "pubkey"], input_data=private + "\n").strip()
    except WireGuardError:
        return ""


def build_config(
    private_key: str,
    client_ip: str,
    server_public_key: str,
    endpoint: str,
    subnet_cidr: str = "10.0.0.0/24",
    mtu: int = 1420,
    keepalive: int = 25,
) -> str:
    if not valid_key(private_key):
        raise WireGuardError("clave privada inválida")
    if not valid_key(server_public_key):
        raise WireGuardError("clave pública del servidor inválida")
    network = validate_subnet(subnet_cidr)
    address = validate_address(client_ip, subnet_cidr)
    endpoint, _ = validate_endpoint(endpoint)
    if not (1280 <= int(mtu) <= 1500):
        raise WireGuardError("MTU fuera de rango")
    if not (0 <= int(keepalive) <= 65535):
        raise WireGuardError("keepalive fuera de rango")
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {address}/{network.prefixlen}\n"
        f"MTU = {int(mtu)}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {network}\n"
        f"PersistentKeepalive = {int(keepalive)}\n"
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

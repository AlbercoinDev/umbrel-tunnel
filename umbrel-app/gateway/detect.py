"""Detección de servicios expuestos por las apps de Umbrel.

Fuentes, en orden:
1. API de Docker (a través del socket-proxy): contenedores en ejecución, sus
   redes y puertos.
2. exports.sh de cada app en /umbrel-app-data: IPs y puertos publicados por
   Umbrel cuando Docker no está disponible.
3. Servicios del host (SSH, panel de UmbrelOS).
"""

from __future__ import annotations

import os
import re
import socket
import struct
from pathlib import Path

import catalog
from docker_api import DockerClient, DockerError

APP_DATA = Path(os.environ.get("UMBREL_APP_DATA", "/umbrel-app-data"))
NETWORK = os.environ.get("UMBREL_NETWORK", "umbrel_main_network")
HOST_SERVICES = os.environ.get("TUNNEL_WG_HOST_SERVICES", "1") not in {"0", "false", "no"}

IGNORED_PROJECTS = {"tunnel-wg", "app_proxy", "app-proxy", "socket-proxy"}
IGNORED_PORTS = {2375, 8081}
EXPORT_RE = re.compile(r"""^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=["']?([^"'\n]*)["']?""", re.MULTILINE)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _manifest_name(app_id: str) -> str:
    manifest = APP_DATA / app_id / "umbrel-app.yml"
    try:
        for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("name:"):
                value = line.split(":", 1)[1].strip().strip("\"'")
                if value:
                    return value
    except OSError:
        pass
    return catalog.app_name(app_id)


def _parse_exports(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    result: dict[str, str] = {}
    for match in EXPORT_RE.finditer(text):
        result[match.group(1)] = match.group(2).strip()
    return result


def _app_id_from_name(name: str, labels: dict) -> str:
    project = labels.get("com.docker.compose.project") or labels.get("com.docker.compose.project.working_dir")
    if project:
        return str(project).rstrip("/").split("/")[-1]
    # Nombres típicos de Umbrel: bitcoin_bitcoind_1, bitcoin-bitcoind-1.
    return re.split(r"[_-]", name, maxsplit=1)[0]


def _service_from_name(name: str, labels: dict) -> str:
    service = labels.get("com.docker.compose.service")
    if service:
        return str(service)
    parts = re.split(r"[_-]", name)
    return parts[1] if len(parts) > 1 else name


def _container_ip(container: dict) -> str | None:
    networks = (container.get("NetworkSettings") or {}).get("Networks") or {}
    if NETWORK in networks and networks[NETWORK].get("IPAddress"):
        return networks[NETWORK]["IPAddress"]
    for data in networks.values():
        ip = (data or {}).get("IPAddress")
        if ip:
            return ip
    return None


def _container_ports(container: dict, client: DockerClient) -> set[int]:
    ports: set[int] = set()
    for entry in container.get("Ports") or []:
        if entry.get("Type") == "tcp" and entry.get("PrivatePort"):
            try:
                ports.add(int(entry["PrivatePort"]))
            except (TypeError, ValueError):
                pass
    if not ports:
        # Algunas imágenes no publican Ports en /containers/json.
        try:
            detail = client.inspect(container.get("Id", ""))
        except DockerError:
            detail = {}
        exposed = ((detail.get("Config") or {}).get("ExposedPorts") or {})
        for key in exposed:
            if str(key).endswith("/tcp"):
                try:
                    ports.add(int(str(key).split("/", 1)[0]))
                except ValueError:
                    pass
    return ports


def _service_entry(
    app_id: str,
    app: str,
    service: str,
    ip: str,
    port: int,
    source: str,
    system: bool = False,
    meta: dict | None = None,
) -> dict:
    meta = meta or {}
    name = meta.get("name") or f"{service} ({port})"
    return {
        "id": f"{app_id}:{service}:{port}",
        "app_id": app_id,
        "app": app,
        "service": service,
        "name": name,
        "target_ip": ip,
        "target_port": port,
        "protocol": "tcp",
        "sensitive": bool(meta.get("sensitive", False)),
        "system": system,
        "description": meta.get("description", ""),
        "source": source,
    }


def _detect_docker() -> list[dict]:
    try:
        client = DockerClient()
        containers = client.containers()
    except DockerError:
        return []

    services: list[dict] = []
    for container in containers:
        names = container.get("Names") or []
        raw_name = names[0].lstrip("/") if names else ""
        labels = container.get("Labels") or {}
        app_id = _app_id_from_name(raw_name, labels)
        if app_id in IGNORED_PROJECTS:
            continue
        if any(token in raw_name for token in ("app_proxy", "app-proxy", "socket-proxy")):
            continue
        ip = _container_ip(container)
        if not ip:
            continue
        service = _service_from_name(raw_name, labels)
        app = _manifest_name(app_id)
        for port in sorted(_container_ports(container, client)):
            if port in IGNORED_PORTS:
                continue
            meta = catalog.service_for(app_id, port)
            services.append(_service_entry(app_id, app, service, ip, port, "docker", meta=meta))
    return services


def _first_ip(exports: dict[str, str], app_id: str) -> str | None:
    for var in catalog.ip_vars(app_id):
        value = exports.get(var, "")
        if IPV4_RE.match(value):
            return value
    # Heurística: cualquier APP_<APP>_*_IP.
    for key, value in exports.items():
        if key.endswith("_IP") and IPV4_RE.match(value):
            return value
    return None


def _detect_exports() -> list[dict]:
    services: list[dict] = []
    if not APP_DATA.is_dir():
        return services
    for app_dir in sorted(APP_DATA.iterdir()):
        if not app_dir.is_dir():
            continue
        app_id = app_dir.name
        exports = _parse_exports(app_dir / "exports.sh")
        if not exports:
            continue
        ip = _first_ip(exports, app_id)
        if not ip:
            continue
        app = _manifest_name(app_id)
        entry = catalog.CATALOG.get(app_id)
        if entry:
            for svc in entry["services"]:
                port = svc["port"]
                for var in svc.get("port_vars", []):
                    value = exports.get(var, "")
                    if value.isdigit():
                        port = int(value)
                        break
                services.append(
                    _service_entry(app_id, app, svc["name"], ip, port, "exports", meta=svc)
                )
        else:
            # App desconocida: cada APP_*_PORT con su IP.
            for key, value in exports.items():
                if not key.endswith("_PORT") or not value.isdigit():
                    continue
                port = int(value)
                if not (1 <= port <= 65535):
                    continue
                services.append(
                    _service_entry(app_id, app, key.removeprefix("APP_").removesuffix("_PORT").lower(), ip, port, "exports")
                )
    return services


def _default_gateway() -> str | None:
    try:
        with open("/proc/net/route", encoding="ascii") as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) < 4 or parts[1] != "00000000":
                    continue
                flags = int(parts[3], 16)
                if not flags & 0x0002:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
    except (OSError, ValueError):
        pass
    return None


def _port_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _detect_host() -> list[dict]:
    if not HOST_SERVICES:
        return []
    ip = _default_gateway()
    if not ip:
        return []
    services: list[dict] = []
    for svc in catalog.SYSTEM_SERVICES:
        if _port_open(ip, svc["port"]):
            services.append(
                _service_entry(
                    "umbrel-os",
                    "UmbrelOS",
                    svc["id"],
                    ip,
                    svc["port"],
                    "system",
                    system=True,
                    meta=svc,
                )
            )
    return services


def detect_services() -> list[dict]:
    services = _detect_docker()
    if not services:
        services = _detect_exports()
    services.extend(_detect_host())

    unique: dict[str, dict] = {}
    for svc in services:
        unique.setdefault(svc["id"], svc)
    return sorted(unique.values(), key=lambda s: (s["system"], s["app"].lower(), s["target_port"]))


def find_service(service_id: str) -> dict | None:
    for svc in detect_services():
        if svc["id"] == service_id:
            return svc
    return None

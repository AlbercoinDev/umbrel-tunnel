"""Detección de servicios expuestos por las apps de Umbrel.

The gateway never talks to the Docker daemon. Umbrel installs every app in
``${UMBREL_ROOT}/app-data/<app-id>`` and keeps the rendered ``umbrel-app.yml``
and ``docker-compose.yml`` there, so the gateway can read those files read-only
and use Docker DNS names (``<app-id>_<service>_1``) as targets.

Security rules:
- only regular files below the app-data root are read, never symlinks;
- ``exports.sh`` is never executed, only scanned with a static regex;
- environment values and app data are never returned by the API;
- unknown apps remain available through the manual service form.
"""

from __future__ import annotations

import json
import ipaddress
import os
import re
import socket
import struct
from pathlib import Path

import catalog

try:  # PyYAML is installed in the image; the fallback keeps imports testable.
    import yaml
except ImportError:  # pragma: no cover - the container always ships PyYAML
    yaml = None

APP_DATA = Path(os.environ.get("UMBREL_APP_DATA", "/umbrel-app-data"))
HOST_SERVICES = os.environ.get("UMBREL_TUNNEL_HOST_SERVICES", "1") not in {"0", "false", "no"}

IGNORED_APPS = {
    "albercoin-store-umbrel-tunnel",
    "umbrel-tunnel",
    "app_proxy",
    "app-proxy",
    "socket-proxy",
}
IGNORED_PORTS = {2375, 8081}
MAX_FILE_SIZE = 512 * 1024
EXPORT_RE = re.compile(r"""^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=["']?([^"'\n]*)["']?""", re.MULTILINE)
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
SENSITIVE_HINTS = ("postgres", "mysql", "mariadb", "mongo", "redis", "admin", "rpc", "grpc", "docker", "portainer")


def _read_text(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        if path.stat().st_size > MAX_FILE_SIZE:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_yaml(path: Path) -> dict:
    text = _read_text(path)
    if not text or yaml is None:
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _load_json(path: Path) -> dict:
    text = _read_text(path)
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _gateway_config(app_dir: Path) -> tuple[str, int]:
    """Read umbreld's resolved app_proxy target without executing anything.

    Modern umbrelOS writes ``app-gateway.json`` next to the installed compose
    file with the interpolated ``APP_HOST``/``APP_PORT`` values. It is more
    reliable than the raw compose environment, which can contain ``${...}``.
    """
    data = _load_json(app_dir / "app-gateway.json")
    host = str(data.get("APP_HOST") or "").strip()
    try:
        port = int(str(data.get("APP_PORT") or "").strip())
    except (TypeError, ValueError):
        port = 0
    return host, port


def _manifest_name(app_id: str) -> str:
    manifest = _load_yaml(APP_DATA / app_id / "umbrel-app.yml")
    name = str(manifest.get("name") or "").strip()
    return name or catalog.app_name(app_id)


def _parse_exports(path: Path) -> dict[str, str]:
    """Read static ``export KEY=value`` lines without executing the file."""
    result: dict[str, str] = {}
    for match in EXPORT_RE.finditer(_read_text(path)):
        result[match.group(1)] = match.group(2).strip()
    return result


def _environment(service: dict) -> dict[str, str]:
    env = service.get("environment")
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items() if v is not None}
    if isinstance(env, list):
        result: dict[str, str] = {}
        for item in env:
            key, sep, value = str(item).partition("=")
            if sep:
                result[key] = value
        return result
    return {}


def _sensitive(app_id: str, service: str, port: int) -> bool:
    meta = catalog.service_for(app_id, port)
    if meta and meta.get("sensitive"):
        return True
    lowered = service.lower()
    return any(hint in lowered for hint in SENSITIVE_HINTS)


def _entry(
    app_id: str,
    app: str,
    service: str,
    host: str,
    port: int,
    protocol: str = "tcp",
    source: str = "app-data",
    system: bool = False,
    sensitive: bool | None = None,
    description: str = "",
    name_key: str = "",
) -> dict | None:
    host = (host or "").strip()
    if not HOST_RE.match(host) or not (1 <= int(port) <= 65535):
        return None
    # Never let a manifest point the proxy back at the gateway itself.
    if host == "localhost" or host.startswith("127.") or host == "0.0.0.0":
        return None
    protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
    meta = catalog.service_for(app_id, port)
    name = (meta or {}).get("name") or f"{service} ({port})"
    return {
        "id": f"{app_id}:{service}:{port}:{protocol}",
        "app_id": app_id,
        "app": app,
        "service": service,
        "name": name,
        "name_key": name_key,
        "target_ip": host,
        "target_port": int(port),
        "protocol": protocol,
        "sensitive": bool(sensitive if sensitive is not None else _sensitive(app_id, service, int(port))),
        "system": system,
        "description": (meta or {}).get("description", description),
        "source": source,
    }


def _ports_from_service(service: dict) -> list[tuple[int, str]]:
    ports: list[tuple[int, str]] = []
    raw_ports = service.get("ports")
    if isinstance(raw_ports, list):
        for item in raw_ports:
            if isinstance(item, dict):
                try:
                    target = int(item.get("target"))
                except (TypeError, ValueError):
                    continue
                protocol = str(item.get("protocol") or "tcp").lower()
                ports.append((target, protocol))
                continue
            text = str(item).strip()
            if not text:
                continue
            protocol = "tcp"
            if "/" in text:
                text, protocol = text.rsplit("/", 1)
            parts = text.split(":")
            try:
                target = int(parts[-1])
            except (TypeError, ValueError):
                continue
            ports.append((target, protocol.lower()))
    return ports


def _container_identity(host: str, services: dict, app_id: str, exports: dict | None = None) -> tuple[str, str] | None:
    """Identify a compose service, never deriving a service name from an IP.

    Exact compose metadata wins. For dynamic addresses, compare Docker DNS
    results only within this app. Ambiguous matches are not safe to guess.
    """
    candidates = []
    matches = []
    for name, service in services.items():
        if name in {"app_proxy", "app-proxy"} or not isinstance(service, dict):
            continue
        container = str(service.get("container_name") or f"{app_id}_{name}_1")
        aliases = {name, container}
        networks = service.get("networks") or {}
        if isinstance(networks, dict):
            for network in networks.values():
                if isinstance(network, dict):
                    address = str(network.get("ipv4_address") or "")
                    if address.startswith("${") and address.endswith("}"):
                        address = (exports or {}).get(address[2:-1], address)
                    aliases.add(address)
                    aliases.update(str(alias) for alias in network.get("aliases", []) or [])
        candidates.append((name, container))
        if host in aliases:
            matches.append((name, container))
    if matches:
        return matches[0] if len(matches) == 1 else None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    for name, container in candidates:
        if _resolved_ip(container) == host:
            matches.append((name, container))
    return matches[0] if len(matches) == 1 else None


def _container_target(host: str, services: dict, app_id: str, exports: dict | None = None) -> str:
    identity = _container_identity(host, services, app_id, exports)
    return identity[1] if identity else host


def _resolved_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except OSError:
            return ""


def canonical_target(host: str, app_id: str) -> str:
    """Upgrade saved detected targets, never guessing manual/system hosts."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", app_id) or app_id in {"manual", "umbrel-os"}:
        return host
    app_dir = APP_DATA / app_id
    if app_dir.is_symlink():
        return host
    services = _load_yaml(app_dir / "docker-compose.yml").get("services") or {}
    if not isinstance(services, dict):
        return host
    return _container_target(host, services, app_id, _parse_exports(app_dir / "exports.sh"))


def _detect_apps() -> list[dict]:
    services: list[dict] = []
    if not APP_DATA.is_dir():
        return services
    for app_dir in sorted(APP_DATA.iterdir()):
        if app_dir.name.startswith(".") or app_dir.is_symlink() or not app_dir.is_dir():
            continue
        app_id = app_dir.name
        if app_id in IGNORED_APPS:
            continue
        manifest = _load_yaml(app_dir / "umbrel-app.yml")
        compose = _load_yaml(app_dir / "docker-compose.yml")
        app = str(manifest.get("name") or catalog.app_name(app_id))
        compose_services = compose.get("services")
        if not isinstance(compose_services, dict):
            compose_services = {}

        seen: set[tuple[str, int, str]] = set()
        app_entries: list[dict] = []

        # Primary source: umbreld's resolved app_proxy target. Fall back to the
        # raw compose environment for older installations.
        host, port = _gateway_config(app_dir)
        if not host or not port:
            proxy = compose_services.get("app_proxy")
            if isinstance(proxy, dict):
                env = _environment(proxy)
                host = str(env.get("APP_HOST") or "").strip()
                try:
                    port = int(str(env.get("APP_PORT") or "").strip())
                except (TypeError, ValueError):
                    port = 0
        if not port:
            try:
                port = int(manifest.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
        if host and port:
            exports = _parse_exports(app_dir / "exports.sh")
            if host.startswith("${") and host.endswith("}"):
                host = exports.get(host[2:-1], host)
            identity = _container_identity(host, compose_services, app_id, exports)
            service_name, container = identity or ("unidentified", "")
            host = container or host
            entry = _entry(app_id, app, service_name, host, port)
            if entry:
                entry["container_name"] = container
                entry["service_identified"] = identity is not None
                app_entries.append(entry)
                seen.add((host, port, "tcp"))

        # Raw published ports are intentional protocol endpoints (P2P, RPC,
        # databases, etc.). Container-internal "expose" entries are ignored.
        for service_name, service in compose_services.items():
            if service_name in {"app_proxy", "app-proxy"} or not isinstance(service, dict):
                continue
            container = str(service.get("container_name") or f"{app_id}_{service_name}_1")
            for port, protocol in _ports_from_service(service):
                key = (container, port, protocol)
                if key in seen or port in IGNORED_PORTS:
                    continue
                entry = _entry(app_id, app, service_name, container, port, protocol)
                if entry:
                    entry["container_name"] = container
                    entry["service_identified"] = True
                    app_entries.append(entry)
                    seen.add(key)

        # Never attach catalog ports to the web container: multi-container
        # apps (Electrs/Mempool) have distinct protocol backends. Only use
        # endpoints actually declared by the gateway or published ports.

        services.extend(app_entries)

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
        if not _port_open(ip, svc["port"]):
            continue
        entry = _entry(
            "umbrel-os",
            "UmbrelOS",
            svc["id"],
            ip,
            svc["port"],
            source="system",
            system=True,
            sensitive=True,
            description=svc.get("description", ""),
            name_key=f"system.{svc['id']}",
        )
        if entry:
            services.append(entry)
    return services


def manual_entry(item: dict) -> dict | None:
    """Build the service entry for one stored manual service.

    Manual services are looked up directly instead of through the deduplicated
    detection list: a manual entry that points at the same container/port as a
    detected app would otherwise disappear and the UI would report
    ``service_not_found`` when the user tries to open it.
    """
    if not isinstance(item, dict):
        return None
    host = str(item.get("host") or "").strip()
    name = str(item.get("name") or "").strip()[:80]
    protocol = str(item.get("protocol") or "tcp").lower()
    try:
        port = int(item.get("port"))
    except (TypeError, ValueError):
        return None
    entry = _entry(
        "manual",
        "Manual",
        name or f"manual-{port}",
        host,
        port,
        protocol,
        source="manual",
        sensitive=True,
    )
    if entry:
        entry["id"] = f"manual:{item.get('id') or name or port}:{port}:{protocol}"
    return entry


def _manual_entries(manual: list[dict] | None) -> list[dict]:
    result: list[dict] = []
    for item in manual or []:
        entry = manual_entry(item)
        if entry:
            result.append(entry)
    return result


def detect_services(manual: list[dict] | None = None) -> list[dict]:
    services = _detect_apps()
    services.extend(_detect_host())
    services.extend(_manual_entries(manual))

    unique: dict[tuple[str, int, str], dict] = {}
    for svc in services:
        unique.setdefault((svc["target_ip"], svc["target_port"], svc["protocol"]), svc)
    resolved = {}
    for svc in unique.values():
        host = svc["target_ip"]
        if host not in resolved:
            resolved[host] = _resolved_ip(host)
        svc["resolved_ip"] = resolved[host]
    return sorted(unique.values(), key=lambda s: (s["system"], s["app"].lower(), s["target_port"], s["protocol"]))


def find_service(service_id: str, manual: list[dict] | None = None) -> dict | None:
    for svc in detect_services(manual):
        if svc["id"] == service_id:
            return svc
    return None

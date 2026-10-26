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


def _service_name_from_container(container: str, app_id: str) -> str:
    prefix = f"{app_id}_"
    if container.startswith(prefix):
        container = container[len(prefix) :]
    if container.endswith("_1"):
        container = container[:-2]
    return container or "app"


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
            if not text or "${" in text:
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
        proxy_host = ""

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
            proxy_host = host
            service_name = _service_name_from_container(host, app_id)
            entry = _entry(app_id, app, service_name, host, port)
            if entry:
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
                    app_entries.append(entry)
                    seen.add(key)

        # Conservative exports.sh fallback: static APP_*_PORT values for
        # catalog-known apps, only on the already verified app_proxy container.
        # We never guess a container name and never execute the file.
        if proxy_host:
            exports = _parse_exports(app_dir / "exports.sh")
            for known in (catalog.CATALOG.get(app_id) or {}).get("services", []):
                port = int(known["port"])
                for var in known.get("port_vars", []):
                    value = exports.get(var, "")
                    if value.isdigit():
                        port = int(value)
                        break
                key = (proxy_host, port, "tcp")
                if key in seen:
                    continue
                entry = _entry(
                    app_id,
                    app,
                    known["name"],
                    proxy_host,
                    port,
                    source="exports",
                    sensitive=known.get("sensitive"),
                )
                if entry:
                    app_entries.append(entry)
                    seen.add(key)

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


def _manual_entries(manual: list[dict] | None) -> list[dict]:
    result: list[dict] = []
    for item in manual or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        name = str(item.get("name") or "").strip()[:80]
        protocol = str(item.get("protocol") or "tcp").lower()
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
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
            result.append(entry)
    return result


def detect_services(manual: list[dict] | None = None) -> list[dict]:
    services = _detect_apps()
    services.extend(_detect_host())
    services.extend(_manual_entries(manual))

    unique: dict[tuple[str, int, str], dict] = {}
    for svc in services:
        unique.setdefault((svc["target_ip"], svc["target_port"], svc["protocol"]), svc)
    return sorted(unique.values(), key=lambda s: (s["system"], s["app"].lower(), s["target_port"], s["protocol"]))


def find_service(service_id: str, manual: list[dict] | None = None) -> dict | None:
    for svc in detect_services(manual):
        if svc["id"] == service_id:
            return svc
    return None

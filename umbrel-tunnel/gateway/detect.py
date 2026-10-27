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

if yaml is not None:

    class _StaticLoader(yaml.SafeLoader):
        """SafeLoader that does not turn unquoted ``10025:25`` into 601525.

        YAML 1.1 treats ``host:container`` as a base-60 integer when the
        container port is below 60. Docker Compose keeps the scalar as text, so
        preserve it instead of losing ports such as Stalwart's SMTP ``10025:25``.
        """

        def construct_yaml_int(self, node):
            value = self.construct_scalar(node)
            if ":" in value:
                return value
            return super().construct_yaml_int(node)

    # PyYAML registers constructors as plain function references, so overriding
    # the method is not enough: the subclass must register it explicitly.
    _StaticLoader.add_constructor(
        "tag:yaml.org,2002:int", _StaticLoader.construct_yaml_int
    )

else:  # pragma: no cover - the container always ships PyYAML
    _StaticLoader = None

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
# Neko publishes 52000-52100/udp; 256 keeps that range without allowing a
# malicious compose file to generate tens of thousands of entries.
MAX_RANGE_PORTS = 256
EXPORT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
VAR_RE = re.compile(
    r"\$(?:(?P<escaped>\$)"
    r"|\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:(?P<op>:?[-+?])(?P<arg>(?:[^{}]|\{[^{}]*\})*))?\}"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
DYNAMIC_SHELL_RE = re.compile(r"[`]|\$\(|\|\||&&|;\s|>\s|<\s")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
SENSITIVE_HINTS = ("postgres", "mysql", "mariadb", "mongo", "redis", "admin", "rpc", "grpc", "docker", "portainer")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _interpolate(value, values: dict | None = None) -> str:
    """Expand Docker Compose style ``$VAR``/``${VAR:-default}`` references.

    ``exports.sh`` is the source of truth for app addresses and ports. Compose
    supports both ``$VAR`` and ``${VAR}``, modifiers such as ``:-``/``-`` and
    ``:+``/``+``, and ``$$`` as an escaped dollar sign. Unknown variables expand
    to an empty string so a malformed host header cannot be turned into a
    different container name.
    """
    text = str(value if value is not None else "")
    if "$" not in text:
        return text
    resolved = values or {}

    def replace(match: re.Match) -> str:
        if match.group("escaped"):
            return "$"
        name = match.group("braced") or match.group("plain") or ""
        op = match.group("op") or ""
        arg = match.group("arg") or ""
        if "$" in arg:
            arg = _interpolate(arg, resolved)
        is_set = name in resolved
        current = str(resolved.get(name, ""))
        is_nonempty = is_set and current != ""
        if op == ":-":
            return current if is_nonempty else arg
        if op == "-":
            return current if is_set else arg
        if op == ":+":
            return arg if is_nonempty else ""
        if op == "+":
            return arg if is_set else ""
        if op in {":?", "?"}:
            # Compose aborts on a missing required variable. The gateway only
            # reads files and never aborts detection, so leave it unresolved.
            if not is_set or (op == ":?" and not is_nonempty):
                return ""
            return current
        return current if is_set else ""

    return VAR_RE.sub(replace, text)


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
        data = yaml.load(text, Loader=_StaticLoader)
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


def _parse_exports(path: Path, base: dict[str, str] | None = None) -> dict[str, str]:
    """Read static ``KEY=value``/``export KEY=value`` lines safely.

    Used for ``exports.sh`` (sourced by umbreld before Compose runs), the
    project ``.env`` and ``.env.app_proxy``. Docker Compose interpolates the
    app's compose file with these values. Every command substitution
    (``$(...)``), pipeline or redirection is ignored, so only literal
    assignments are used. Values are expanded in order, which is enough for
    Umbrel's ``APP_*_IP``/``APP_*_PORT`` variables.
    """
    result: dict[str, str] = {}
    resolved = dict(base or {})
    for line in _read_text(path).splitlines():
        match = EXPORT_RE.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2).strip()
        if not raw:
            value = ""
        else:
            quoted = re.match(r"""^(['"])(.*?)\1(?:\s+#.*)?$""", raw)
            if quoted:
                value = quoted.group(2)
            else:
                value = re.sub(r"\s+#.*$", "", raw).strip()
                if value[:1] in {"'", '"'} or value[-1:] in {"'", '"'}:
                    # Unbalanced quotes mean the assignment is not a literal.
                    continue
        if DYNAMIC_SHELL_RE.search(value):
            continue
        if "$" in value:
            value = _interpolate(value, resolved)
        resolved[key] = value
        result[key] = value
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


def _compose_values(
    app_id: str,
    exports: dict[str, str] | None = None,
    app_dir: Path | None = None,
) -> dict[str, str]:
    """Environment used to interpolate an app's compose file.

    Compose reads the project ``.env`` automatically and umbreld exports the
    values from ``exports.sh``, so both are considered. ``exports.sh`` wins over
    ``.env`` because shell variables override the dotenv file. Catalog defaults
    fill the gaps for known apps when the files are missing or unreadable.
    """
    values: dict[str, str] = {}
    if app_dir is not None:
        values.update(_parse_exports(app_dir / ".env"))
    values.update(exports or {})
    for var, port in catalog.port_defaults(app_id).items():
        if not values.get(var):
            values[var] = str(port)
    return values


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
    meta: dict | None = None,
) -> dict | None:
    host = (host or "").strip()
    if not HOST_RE.match(host) or not (1 <= int(port) <= 65535):
        return None
    # Never let a manifest point the proxy back at the gateway itself.
    if host == "localhost" or host.startswith("127.") or host == "0.0.0.0":
        return None
    protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
    if meta is None:
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


def _port_numbers(value) -> list[int]:
    """Parse ``80``, ``8000-8010`` and reject anything outside 1..65535."""
    text = str(value if value is not None else "").strip()
    if not text:
        return []
    if "-" in text:
        start, _, end = text.partition("-")
        try:
            first, last = int(start), int(end)
        except (TypeError, ValueError):
            return []
        if not (1 <= first <= last <= 65535) or last - first + 1 > MAX_RANGE_PORTS:
            return []
        return list(range(first, last + 1))
    try:
        port = int(text)
    except (TypeError, ValueError):
        return []
    return [port] if 1 <= port <= 65535 else []


def _ports_from_service(service: dict, values: dict | None = None) -> list[tuple[int, str]]:
    """Return ``(container_port, protocol)`` for a compose service's ``ports``.

    Only the container side matters: the gateway reaches the app container over
    Docker's network, not through the host port. Both Compose syntaxes are
    supported (short ``"HOST:CONTAINER/PROTO"`` and long dictionaries), as are
    variable references and port ranges.
    """
    ports: list[tuple[int, str]] = []
    raw_ports = service.get("ports")
    if not isinstance(raw_ports, list):
        return ports
    for item in raw_ports:
        if isinstance(item, dict):
            protocol = _interpolate(item.get("protocol") or "tcp", values).strip().lower()
            protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
            for target in _port_numbers(_interpolate(item.get("target"), values)):
                ports.append((target, protocol))
            continue
        text = _interpolate(item, values).strip()
        if not text:
            continue
        protocol = "tcp"
        if "/" in text:
            text, protocol = text.rsplit("/", 1)
        # The container port is the last colon-separated field. This also
        # handles "[::1]:8080:80" and unresolved host-side variables.
        target = text.rsplit(":", 1)[-1]
        protocol = _interpolate(protocol, values).strip().lower()
        protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
        for port in _port_numbers(target):
            ports.append((port, protocol))
    return ports


def _ports_from_expose(service: dict, values: dict | None = None) -> list[tuple[int, str]]:
    """``expose`` lists internal ports; they are reachable from the tunnel.

    The Compose spec only defines TCP here, but some files append ``/udp`` to
    mirror ``ports``; honour it when present.
    """
    ports: list[tuple[int, str]] = []
    raw = service.get("expose")
    if not isinstance(raw, list):
        return ports
    for item in raw:
        text = _interpolate(item, values).strip()
        protocol = "tcp"
        if "/" in text:
            text, protocol = text.rsplit("/", 1)
            protocol = _interpolate(protocol, values).strip().lower()
            protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
        for port in _port_numbers(text):
            ports.append((port, protocol))
    return ports


def _service_container(app_id: str, name: str, service: dict, values: dict | None = None) -> str:
    container = _interpolate(service.get("container_name") or "", values).strip()
    return container or f"{app_id}_{name}_1"


def _network_mode(service: dict) -> str:
    return str(service.get("network_mode") or "").strip().strip("'\"")


def _is_host_network(service: dict) -> bool:
    return _network_mode(service) == "host"


def _container_identity(host: str, services: dict, app_id: str, values: dict | None = None) -> tuple[str, str] | None:
    """Identify a compose service, never deriving a service name from an IP.

    Exact compose metadata wins. For dynamic addresses, compare Docker DNS
    results only within this app. Ambiguous matches are not safe to guess.
    """
    host = _interpolate(host, values).strip()
    candidates = []
    matches = []
    for name, service in services.items():
        if name in {"app_proxy", "app-proxy"} or not isinstance(service, dict):
            continue
        container = _service_container(app_id, name, service, values)
        aliases = {name, container}
        hostname = _interpolate(service.get("hostname") or "", values).strip()
        if hostname:
            aliases.add(hostname)
        networks = service.get("networks")
        if isinstance(networks, dict):
            for network in networks.values():
                if not isinstance(network, dict):
                    continue
                address = _interpolate(network.get("ipv4_address") or "", values).strip()
                if address:
                    aliases.add(address)
                for alias in network.get("aliases") or []:
                    alias = _interpolate(alias, values).strip()
                    if alias:
                        aliases.add(alias)
        elif isinstance(networks, list):
            for network in networks:
                if isinstance(network, dict):
                    for alias in network.get("aliases") or []:
                        alias = _interpolate(alias, values).strip()
                        if alias:
                            aliases.add(alias)
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


def _container_target(host: str, services: dict, app_id: str, values: dict | None = None) -> str:
    identity = _container_identity(host, services, app_id, values)
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
    values = _compose_values(
        app_id,
        _parse_exports(app_dir / "exports.sh"),
        app_dir,
    )
    return _container_target(host, services, app_id, values)


def _manifest_port(manifest: dict) -> int:
    try:
        return int(manifest.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def _service_target(
    app_id: str,
    name: str,
    service: dict,
    services: dict,
    host_ip: str,
    values: dict | None = None,
) -> str:
    """Resolve the address the gateway must use for a compose service."""
    mode = _network_mode(service)
    if mode == "host":
        return host_ip
    if mode.startswith("service:"):
        other_name = mode.split(":", 1)[1].strip()
        other = services.get(other_name)
        if isinstance(other, dict):
            if _is_host_network(other):
                return host_ip
            return _service_container(app_id, other_name, other, values)
    if mode.startswith("container:"):
        return mode.split(":", 1)[1].strip()
    return _service_container(app_id, name, service, values)


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

        exports = _parse_exports(app_dir / "exports.sh")
        values = _compose_values(app_id, exports, app_dir)
        # umbreld merges .env.app_proxy on top of app_proxy's environment (and
        # on top of app-gateway.json) before starting its in-process gateway.
        proxy_overrides = _parse_exports(app_dir / ".env.app_proxy", values)
        proxy_values = {**values, **proxy_overrides}
        host_ip = _host_ip()

        seen: set[tuple[str, int, str]] = set()
        app_entries: list[dict] = []
        proxy_entry = False

        # Host-network services (Home Assistant, Pi-hole, Plex, …) are not on
        # Docker's network. They listen on the Umbrel host, which the gateway
        # reaches through the default Docker gateway.
        host_network_services = [
            (name, service)
            for name, service in compose_services.items()
            if name not in {"app_proxy", "app-proxy"}
            and isinstance(service, dict)
            and _is_host_network(service)
        ]

        # Primary source: umbreld's resolved app_proxy target. Fall back to the
        # raw compose environment for older installations.
        host, port = _gateway_config(app_dir)
        if not host or not port:
            proxy = compose_services.get("app_proxy")
            if isinstance(proxy, dict):
                env = _environment(proxy)
                host = env.get("APP_HOST") or ""
                port = env.get("APP_PORT") or ""
        if proxy_overrides.get("APP_HOST"):
            host = proxy_overrides["APP_HOST"]
        if proxy_overrides.get("APP_PORT"):
            port = proxy_overrides["APP_PORT"]
        host = _interpolate(host, proxy_values).strip() if host else ""
        try:
            port = int(_interpolate(port, proxy_values).strip()) if port else 0
        except (TypeError, ValueError):
            port = 0

        if host and port:
            proxy_entry = True
            if host in LOOPBACK_HOSTS or host.startswith("127."):
                # Some host-network apps expose 127.0.0.1 through app_proxy.
                host = host_ip or host
            identity = _container_identity(host, compose_services, app_id, proxy_values)
            if identity:
                service_name, container = identity
                identified = compose_services.get(service_name)
                target = (
                    _service_target(app_id, service_name, identified, compose_services, host_ip, proxy_values)
                    if isinstance(identified, dict)
                    else container
                )
            else:
                service_name, container, target = "unidentified", "", host
            entry = _entry(app_id, app, service_name, target, port)
            if entry:
                entry["container_name"] = target if identity else ""
                entry["service_identified"] = identity is not None
                app_entries.append(entry)
                seen.add((entry["target_ip"], port, "tcp"))

        # Published and exposed container ports are intentional protocol
        # endpoints (P2P, RPC, ZMQ, databases, …). Only the container side is
        # used so the proxy survives container IP changes.
        for service_name, service in compose_services.items():
            if service_name in {"app_proxy", "app-proxy"} or not isinstance(service, dict):
                continue
            if _is_host_network(service):
                continue
            target = _service_target(app_id, service_name, service, compose_services, host_ip, values)
            if not target:
                continue
            for port, protocol in _ports_from_service(service, values) + _ports_from_expose(service, values):
                key = (target, port, protocol)
                if key in seen or port in IGNORED_PORTS:
                    continue
                entry = _entry(app_id, app, service_name, target, port, protocol)
                if entry:
                    entry["container_name"] = target
                    entry["service_identified"] = True
                    app_entries.append(entry)
                    seen.add(key)

        # Host-network apps have no app_proxy in most cases (Home Assistant,
        # Pi-hole, Plex, …). Their published ports are on the Umbrel host and
        # the manifest port is the web UI.
        if host_network_services and host_ip:
            for service_name, service in host_network_services:
                for port, protocol in _ports_from_service(service, values):
                    key = (host_ip, port, protocol)
                    if key in seen or port in IGNORED_PORTS:
                        continue
                    entry = _entry(app_id, app, service_name, host_ip, port, protocol)
                    if entry:
                        entry["container_name"] = host_ip
                        entry["service_identified"] = True
                        app_entries.append(entry)
                        seen.add(key)
            manifest_port = _manifest_port(manifest)
            key = (host_ip, manifest_port, "tcp")
            if manifest_port and not proxy_entry and key not in seen and manifest_port not in IGNORED_PORTS:
                service_name = host_network_services[0][0]
                entry = _entry(app_id, app, service_name, host_ip, manifest_port)
                if entry:
                    entry["container_name"] = host_ip
                    entry["service_identified"] = True
                    app_entries.append(entry)
                    seen.add(key)

        # Catalog extras cover ports that are listening inside the container but
        # are not published or exposed in compose (for example Bitcoin Core's
        # ZMQ streams or its whitebind listener). They are always attached to an
        # explicit compose service, never to an arbitrary web container.
        for meta in catalog.extra_services(app_id, values):
            service_name = str(meta.get("service") or "")
            service = compose_services.get(service_name)
            if not isinstance(service, dict):
                continue
            target = _service_target(app_id, service_name, service, compose_services, host_ip, values)
            if not target:
                continue
            port = int(meta["port"])
            protocol = str(meta.get("protocol") or "tcp").lower()
            key = (target, port, protocol)
            if key in seen or port in IGNORED_PORTS:
                continue
            entry = _entry(app_id, app, service_name, target, port, protocol, meta=meta)
            if entry:
                entry["container_name"] = target
                entry["service_identified"] = True
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


def _host_ip() -> str:
    """Address of the Umbrel host as seen from the gateway container."""
    return _default_gateway() or ""


def _port_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _detect_host() -> list[dict]:
    if not HOST_SERVICES:
        return []
    ip = _host_ip()
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

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
import scan

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

# Services that expose infrastructure ports we must never infer from a
# command line: they are usually sidecars, databases or the Tor daemon.
INFERRED_SKIP_SERVICES = re.compile(
    r"(?i)(?:^|[-_])(?:db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|"
    r"redis|valkey|memcached|tor|i2pd|relay|queue|rabbitmq|kafka|zookeeper)(?:[-_]|$)"
)
# Sidecars that never listen: a bare ``PORT`` in their environment is a client
# setting, a timeout or a batch size, not a listening socket.
NON_LISTENER_SERVICE_RE = re.compile(
    r"(?i)(?:^|[-_])(?:worker|sidekiq|celery|beat|scheduler|cron|job|jobs|task|"
    r"tasks|migrate|migration|setup|init|initializer)(?:[-_]|$)"
)
# Ports that are commonly bound by infrastructure sidecars. They are still
# listed when they come from an explicit ``ports``/``expose`` declaration; the
# list only filters heuristic listeners in ``environment``/``command``.
INFERRED_BLOCK_PORTS = {
    22, 25, 53, 67, 68, 123, 137, 138, 139, 161, 162, 389, 445, 465, 514,
    587, 636, 993, 995, 2181, 3306, 5432, 5672, 6379, 7656, 9050, 9051,
    9092, 9901, 11211, 27017, 29051,
}
INTERNAL_KINDS = {"database", "metrics"}


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


def _command_texts(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return []


def _last_host_port(value: str) -> int | None:
    text = str(value or "").strip().strip("'\"")
    if not text:
        return None
    text = re.sub(r"(?i)^(?:tcp|udp|ws|wss|http|https)://", "", text)
    match = re.search(r"(?:^|:)(\d{2,5})$", text)
    if not match:
        return None
    port = int(match.group(1))
    return port if 1 <= port <= 65535 else None


WILDCARD_RE = re.compile(r"(?<![\d.])(?:0\.0\.0\.0|\[::\]|\*|(?<!:)::):(\d{2,5})(?!\d)")
SCHEME_RE = re.compile(r"(?i)\b(?:tcp|udp|ws|wss|http|https)://(?:0\.0\.0\.0|\[::\]|\*|::):(\d{2,5})")
BARE_PORT_RE = re.compile(r"^\s*(\d{2,5})\s*$")
# Bind keys that make a bare number a listener: BIND, BIND_PORT, LISTEN_ADDR...
# ``ADDR``/``ADDRESS`` only count at the very end of the name:
# ``NODE_ADDR_FILTER_THRESHOLD`` is a numeric threshold, not a listener.
STRONG_BIND_KEY_RE = re.compile(r"(?i)^(?:BIND|LISTEN)(?:_(?:PORT|ADDR|ADDRESS))?$")
# Keys like ``PORT`` are container conventions and always mean the listen port.
UNCONDITIONAL_PORT_KEYS = frozenset(
    {"PORT", "HTTP_PORT", "HTTPS_PORT", "SERVER_PORT", "WEB_PORT"}
)
# Tokens that describe the protocol, not the owner of the variable. A key such
# as ``MEMPOOL_HTTP_PORT`` belongs to the service whose image is ``mempool``;
# ``LISTEN_HTTP_PORT`` (a project-wide setting reused by every service of an
# app) has no owner and is ignored.
GENERIC_ENV_TOKENS = frozenset(
    {
        "PORT", "PORTS", "HTTP", "HTTPS", "WS", "WSS", "GRPC", "RPC", "P2P",
        "API", "WEB", "DASHBOARD", "METRICS", "ELECTRUM", "LIGHTNING", "ZMQ",
        "ADMIN", "REST", "TCP", "UDP", "SERVER", "SERVICE", "LISTEN", "BIND",
        "ADDR", "ADDRESS", "HOST", "URL", "URI", "PUBLIC", "INTERNAL",
        "EXTERNAL", "LOCAL", "REMOTE", "NODE", "SITE", "APP", "BACKEND",
        "FRONTEND", "PROXY", "CONFIG", "DEFAULT", "SYSTEM", "MAIN",
    }
)
ZMQ_RE = re.compile(r"(?i)-zmq[a-z0-9]+=(?:tcp|udp)://(?:0\.0\.0\.0|\[::\]|\*|::):(\d{2,5})")
BIND_FLAG_RE = re.compile(
    r"(?i)(?:^|\s)--?(?:bind|listen|rpcbind)(?:-[\w.-]+)?(?:=|\s+)([^\s,]+)"
)
PORT_FLAG_RE = re.compile(r"(?i)(?:^|\s)--?([\w.-]*port[\w.-]*)(?:=|\s+)(\d{2,5})\b")
CLIENT_FLAG_RE = re.compile(
    r"(?i)bitcoin-rpcport|daemon|remote|upstream|target|proxy|connect|addnode|seednode"
)


def _env_port_belongs(key: str, service_text: str) -> bool:
    """Return whether a ``*_PORT`` variable belongs to this service.

    Compose files reuse a YAML anchor (``x-environment``) across every service
    of an app. Sharing ``LISTEN_HTTP_PORT`` does not mean the database or the
    worker listens on it, so a bare value is only accepted when the key names
    the service (``MEMPOOL_HTTP_PORT`` in the mempool backend) or uses a generic
    container convention (``PORT``).

    The *last* meaningful token has to name the service: in
    ``CANARY_MEMPOOL_PORT`` the port belongs to mempool, so the canary backend
    must not claim it, while ``MEMPOOL_HTTP_PORT`` belongs to mempool.
    """
    upper = key.upper()
    if upper in UNCONDITIONAL_PORT_KEYS:
        return True
    if not re.search(r"_(?:PORT|PORTS)$", upper):
        return False
    stem = re.sub(r"_(?:PORT|PORTS)$", "", upper)
    tokens = [
        token
        for token in stem.split("_")
        if token not in GENERIC_ENV_TOKENS and len(token) >= 3
    ]
    # Protocol sockets that are always listeners on the publishing side. The
    # variable name does not contain the app name (``ZMQ_RAWBLOCK_PORT`` in the
    # Bitcoin wrapper), but the protocol itself is the evidence.
    if "ZMQ" in stem.split("_") or "WHITEBIND" in stem.split("_"):
        return True
    if not tokens:
        return False
    return tokens[-1].lower() in service_text


def _ports_from_listeners(
    service: dict, values: dict | None = None, name: str = ""
) -> list[tuple[int, str, str, str]]:
    """Infer listener ports from ``environment``/``command``/``entrypoint``.

    Only strong evidence is accepted: a wildcard bind address, an explicit
    ``BIND``/``LISTEN`` variable, a server flag or a bind/listen command-line
    option. Client addresses and infrastructure sidecars are rejected so a
    service is never shown a port it only consumes.
    """
    found: list[tuple[int, str, str, str]] = []
    seen: set[tuple[int, str]] = set()
    service_text = f"{name} {service.get('image') or ''}".lower()

    def add(raw_port, protocol: str, evidence: str, origin: str) -> None:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            return
        protocol = "udp" if protocol == "udp" else "tcp"
        if not (1 <= port <= 65535) or (port, protocol) in seen:
            return
        seen.add((port, protocol))
        found.append((port, protocol, evidence[:120], origin))

    env = _environment(service)
    for key, raw_value in env.items():
        value = _interpolate(raw_value, values).strip()
        if not value:
            continue
        protocol = "udp" if "udp://" in value.lower() else "tcp"
        matches = [match.group(1) for match in SCHEME_RE.finditer(value)]
        matches += [match.group(1) for match in WILDCARD_RE.finditer(value)]
        upper = key.upper()
        bare = BARE_PORT_RE.match(value)
        if STRONG_BIND_KEY_RE.match(upper) or upper.endswith(("_BIND", "_LISTEN")):
            if bare:
                matches.append(bare.group(1))
            elif not matches:
                last = _last_host_port(value)
                if last:
                    matches.append(str(last))
        elif bare and _env_port_belongs(upper, service_text):
            matches.append(bare.group(1))
        for match in matches:
            add(match, protocol, f"{key}={value}", "env")

    for field in ("command", "entrypoint"):
        for text in _command_texts(service.get(field)):
            text = _interpolate(text, values)
            if not text.strip():
                continue
            for match in ZMQ_RE.finditer(text):
                add(match.group(1), "tcp", match.group(0), "command")
            for match in BIND_FLAG_RE.finditer(text):
                last = _last_host_port(match.group(1))
                if last:
                    add(last, "tcp", match.group(0), "command")
            has_rpcbind = "-rpcbind" in text.lower()
            for match in PORT_FLAG_RE.finditer(text):
                flag = match.group(1).lower()
                if CLIENT_FLAG_RE.search(flag) and not (has_rpcbind and flag == "rpcport"):
                    continue
                add(match.group(2), "tcp", match.group(0), "command")
    return found


def _port_hints(service: dict, values: dict | None = None) -> dict[tuple[int, str], str]:
    """Keep the variable names next to each declared port for classification."""
    hints: dict[tuple[int, str], str] = {}
    for field, parser in (("ports", _ports_from_service), ("expose", _ports_from_expose)):
        raw = service.get(field)
        if not isinstance(raw, list):
            continue
        for item in raw:
            raw_text = json.dumps(item) if isinstance(item, dict) else str(item)
            names = re.findall(r"[A-Z][A-Z0-9_]{2,}", raw_text)
            hint = " ".join(name for name in names if re.search(
                r"PORT|BIND|LISTEN|RPC|GRPC|ZMQ|P2P|HTTP|WS|ELECTRUM|LIGHTNING|METRICS|ADMIN",
                name,
            ))
            temp = {field: [item]}
            for port, protocol in parser(temp, values):
                key = (port, protocol)
                hints[key] = (hints.get(key, "") + " " + hint).strip()
    return hints


def _declared_ports(
    service: dict, values: dict | None = None, name: str = ""
) -> list[tuple[int, str, str, str]]:
    """Return ``(port, protocol, source, hint)`` in priority order."""
    hints = _port_hints(service, values)
    entries: list[tuple[int, str, str, str]] = []
    for source, parser in (("compose", _ports_from_service), ("expose", _ports_from_expose)):
        for port, protocol in parser(service, values):
            entries.append((port, protocol, source, hints.get((port, protocol), "")))
    for port, protocol, evidence, origin in _ports_from_listeners(service, values, name):
        entries.append((port, protocol, origin, evidence))
    unique: list[tuple[int, str, str, str]] = []
    seen: set[tuple[int, str]] = set()
    for entry in entries:
        key = (entry[0], entry[1])
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def _looks_http(service_text: str, full_text: str, port: int) -> bool:
    if port in {80, 443}:
        return True
    if re.search(
        r"nginx|caddy|traefik|httpd|apache|tomcat|wordpress|grafana|swagger|openapi",
        full_text,
    ):
        return True
    if re.search(
        r"uvicorn|gunicorn|flask|django|next\b|nuxt\b|vite\b|npm\b|pnpm\b|yarn\b|"
        r"http-server|serve\b|php-fpm",
        full_text,
    ):
        return True
    return bool(
        port > 1024
        and re.search(
            r"(?:^|[-_])(?:web|www|frontend|ui|dashboard|panel|api|app|server)(?:[-_]|$)",
            service_text,
        )
    )


def _classify(
    app_id: str,
    app: str,
    service_name: str,
    service: dict,
    port: int,
    protocol: str,
    hint: str = "",
    http_probe: bool = False,
    prometheus: bool = False,
    proxy: bool = False,
) -> tuple[str, str]:
    """Return ``(kind, confidence)`` for one detected port."""
    if proxy:
        return "http", "high"
    if protocol == "udp":
        return "udp", "medium"
    if prometheus:
        return "metrics", "high"
    if http_probe:
        return "http", "high"

    hint_lower = hint.lower()
    if "zmq" in hint_lower:
        return "zmq", "high"
    if "grpc" in hint_lower:
        return "rpc", "high"
    if "electrum" in hint_lower:
        return "electrum", "high"
    if re.search(r"(?:^|[^a-z0-9])rest(?:[^a-z0-9]|$)", hint_lower) or re.search(
        r"(?:^|[^a-z0-9])admin(?:[^a-z0-9]|$)", hint_lower
    ):
        return "rpc", "high"
    if "metrics" in hint_lower or "prometheus" in hint_lower:
        return "metrics", "high"
    if "p2p" in hint_lower or "whitebind" in hint_lower:
        return "p2p", "high"
    if "http" in hint_lower or "web" in hint_lower or "dashboard" in hint_lower:
        return "http", "high"
    if "lightning" in hint_lower:
        return "lightning", "high"
    if "rpc" in hint_lower:
        return "rpc", "high"

    service_text = f"{service_name} {service.get('image') or ''}".lower()
    full_text = " ".join(
        [
            app_id,
            app,
            service_text,
            hint,
            " ".join(_command_texts(service.get("command"))),
            " ".join(_command_texts(service.get("entrypoint"))),
        ]
    ).lower()

    if re.search(r"zmq", full_text):
        return "zmq", "high" if "zmq" in hint.lower() else "medium"
    if re.search(
        r"postgres|postgresql|mysql|mariadb|mongodb|mongo|redis|valkey|memcached|clickhouse",
        full_text,
    ):
        return "database", "high"
    if re.search(r"prometheus|metrics|telemetry|node_exporter", full_text):
        return "metrics", "medium"
    if re.search(r"grpc", full_text):
        return "rpc", "high"
    if re.search(r"electrumx|electrs|fulcrum", service_text):
        return "electrum", "high"
    if re.search(r"lightningd|\blnd\b|core-lightning|clightning", service_text):
        return "lightning", "high"
    if re.search(r"\brpc\b|json-rpc|rpcport|rpcbind|clnrest|rest-port|admin-port", full_text):
        return "rpc", "medium"
    if re.search(r"\bp2p\b|peer|whitelist|whitebind|addnode|seednode", full_text):
        return "p2p", "medium"
    if _looks_http(service_text, full_text, port):
        return "http", "medium"
    return "tcp", "low"


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
    kind: str = "tcp",
    confidence: str = "low",
    internal: bool | None = None,
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
    if internal is None:
        internal = kind in INTERNAL_KINDS
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
        "kind": kind,
        "confidence": confidence,
        "internal": bool(internal),
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


def _detect_apps_impl() -> tuple[list[dict], dict[str, tuple[str, str, str]]]:
    services: list[dict] = []
    contexts: dict[str, tuple[str, str, str]] = {}
    if not APP_DATA.is_dir():
        return services, contexts
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
            entry = _entry(
                app_id, app, service_name, target, port,
                kind="http", confidence="high", source="proxy", sensitive=True,
            )
            if entry:
                entry["container_name"] = target if identity else ""
                entry["service_identified"] = identity is not None
                app_entries.append(entry)
                seen.add((entry["target_ip"], port, "tcp"))
                if entry["target_ip"] != host_ip:
                    contexts.setdefault(entry["target_ip"], (app_id, app, service_name))

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
            for port, protocol, source, hint in _declared_ports(service, values, service_name):
                if port in IGNORED_PORTS:
                    continue
                if source in {"env", "command"} and (
                    INFERRED_SKIP_SERVICES.search(service_name)
                    or NON_LISTENER_SERVICE_RE.search(service_name)
                    or port in INFERRED_BLOCK_PORTS
                ):
                    continue
                key = (target, port, protocol)
                if key in seen:
                    continue
                kind, confidence = _classify(
                    app_id, app, service_name, service, port, protocol, hint=hint
                )
                entry = _entry(
                    app_id, app, service_name, target, port, protocol,
                    source=source, kind=kind, confidence=confidence,
                )
                if entry:
                    entry["container_name"] = target
                    entry["service_identified"] = True
                    app_entries.append(entry)
                    seen.add(key)
                    if target != host_ip:
                        contexts.setdefault(target, (app_id, app, service_name))

        # Host-network apps have no app_proxy in most cases (Home Assistant,
        # Pi-hole, Plex, …). Their published ports are on the Umbrel host and
        # the manifest port is the web UI.
        if host_network_services and host_ip:
            for service_name, service in host_network_services:
                for port, protocol, source, hint in _declared_ports(service, values, service_name):
                    if port in IGNORED_PORTS:
                        continue
                    if source in {"env", "command"} and (
                        INFERRED_SKIP_SERVICES.search(service_name)
                        or NON_LISTENER_SERVICE_RE.search(service_name)
                        or port in INFERRED_BLOCK_PORTS
                    ):
                        continue
                    key = (host_ip, port, protocol)
                    if key in seen:
                        continue
                    kind, confidence = _classify(
                        app_id, app, service_name, service, port, protocol, hint=hint
                    )
                    entry = _entry(
                        app_id, app, service_name, host_ip, port, protocol,
                        source=source, kind=kind, confidence=confidence,
                    )
                    if entry:
                        entry["container_name"] = host_ip
                        entry["service_identified"] = True
                        app_entries.append(entry)
                        seen.add(key)
            manifest_port = _manifest_port(manifest)
            key = (host_ip, manifest_port, "tcp")
            if manifest_port and not proxy_entry and key not in seen and manifest_port not in IGNORED_PORTS:
                service_name = host_network_services[0][0]
                entry = _entry(
                    app_id, app, service_name, host_ip, manifest_port,
                    source="manifest", kind="http", confidence="medium",
                )
                if entry:
                    entry["container_name"] = host_ip
                    entry["service_identified"] = True
                    app_entries.append(entry)
                    seen.add(key)

        # A client setting is never the service's own listener. When another
        # service of the same app declares the port (``ports``/``expose``, the
        # app proxy, a manifest or a server command flag), drop the weak
        # ``environment`` inference from this one. This keeps, for example,
        # ``BITCOIN_RPC_PORT=18443`` off the dashboard container.
        strong = {
            (entry["target_port"], entry["protocol"], entry["target_ip"])
            for entry in app_entries
            if entry["source"] in {"compose", "expose", "proxy", "manifest", "command"}
        }
        if strong:
            app_entries = [
                entry
                for entry in app_entries
                if not (
                    entry["source"] == "env"
                    and any(
                        port == entry["target_port"]
                        and protocol == entry["protocol"]
                        and target != entry["target_ip"]
                        for port, protocol, target in strong
                    )
                )
            ]

        # The catalog is no longer a source of ports. Ports come from the app's
        # own Compose/environment/command declarations or from the active scan,
        # so unknown apps and future versions are detected the same way.
        services.extend(app_entries)

    return services, contexts


def _detect_apps() -> list[dict]:
    services, _ = _detect_apps_impl()
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
            kind="http" if str(svc["id"]).startswith("umbrel-dashboard") else "tcp",
            confidence="high" if str(svc["id"]).startswith("umbrel-dashboard") else "medium",
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
        kind="udp" if protocol == "udp" else "tcp",
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


def _merge_scan(
    services: list[dict],
    contexts: dict[str, tuple[str, str, str]],
) -> list[dict]:
    """Merge active-scan results with the declarative detection.

    Declarative entries win: a scan can only confirm/upgrade an existing port or
    add a port that no file declared (for example an image-only ``EXPOSE``).
    """
    if not contexts:
        return services
    priority = {
        int(svc["target_port"])
        for svc in services
        if svc.get("target_ip") in contexts and svc.get("protocol") == "tcp"
    }
    scan.ensure(list(contexts), priority)
    found = scan.snapshot()
    if not found:
        return services

    by_key = {
        (svc["target_ip"], int(svc["target_port"]), svc.get("protocol", "tcp")): svc
        for svc in services
    }
    for host, ports in found.items():
        meta = contexts.get(host)
        if not meta:
            continue
        app_id, app, service_name = meta
        for port, info in sorted(ports.items()):
            key = (host, int(port), "tcp")
            current = by_key.get(key)
            if current is not None:
                if info.get("http") and current.get("kind") in {"tcp", "http"}:
                    current["kind"] = "metrics" if info.get("prometheus") else "http"
                    current["confidence"] = "high"
                    current["internal"] = current.get("kind") in INTERNAL_KINDS
                continue
            kind = "metrics" if info.get("prometheus") else ("http" if info.get("http") else "tcp")
            entry = _entry(
                app_id,
                app,
                service_name,
                host,
                int(port),
                "tcp",
                source="scan",
                kind=kind,
                confidence="high" if kind in {"http", "metrics"} else "low",
            )
            if entry:
                entry["container_name"] = host
                entry["service_identified"] = True
                services.append(entry)
                by_key[key] = entry
    return services


def detect_services(manual: list[dict] | None = None, scan_network: bool = True) -> list[dict]:
    services, contexts = _detect_apps_impl()
    services.extend(_detect_host())
    services.extend(_manual_entries(manual))
    if scan_network and scan.ENABLED:
        services = _merge_scan(services, contexts)

    unique: dict[tuple[str, int, str], dict] = {}
    for svc in services:
        unique.setdefault((svc["target_ip"], svc["target_port"], svc["protocol"]), svc)
    resolved = {}
    for svc in unique.values():
        host = svc["target_ip"]
        if host not in resolved:
            resolved[host] = _resolved_ip(host)
        svc["resolved_ip"] = resolved[host]
    return sorted(
        unique.values(),
        key=lambda s: (s["system"], s["app"].lower(), s["target_port"], s["protocol"]),
    )


def find_service(service_id: str, manual: list[dict] | None = None) -> dict | None:
    for svc in detect_services(manual):
        if svc["id"] == service_id:
            return svc
    return None

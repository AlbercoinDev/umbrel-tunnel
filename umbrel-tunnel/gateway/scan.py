"""Descubrimiento activo de puertos de los contenedores de Umbrel.

The gateway never mounts the Docker socket. Umbrel apps share a Docker network,
so the gateway can resolve ``<app>_<service>_1`` and connect to the container
ports directly. This module performs a bounded TCP scan and an HTTP probe on
the open ports:

- the scan only runs against private/link-local addresses;
- it runs in a background thread and caches results for a few minutes;
- it never scans host-network apps (that would scan the Umbrel host itself);
- only the fact that a port is open and whether it speaks HTTP is stored, never
  response bodies or service data.

The scan is intentionally best-effort: a stopped container simply produces no
extra ports. Ports declared in ``docker-compose.yml`` keep working without the
scan and are handled by :mod:`detect`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ENABLED = os.environ.get("UMBREL_TUNNEL_SCAN", "1") != "0"
TTL = max(30, int(os.environ.get("UMBREL_TUNNEL_SCAN_TTL", "300") or 300))
# Ports above this limit are only scanned when they are declared by the app or
# when an operator opts into a full scan: they are rare, expensive to probe and
# almost always already present in the Compose file.
FULL_SCAN = os.environ.get("UMBREL_TUNNEL_SCAN_FULL", "0") == "1"

PRIORITY_MAX = 65535 if FULL_SCAN else 10000
CONCURRENCY = 512
CONNECT_TIMEOUT = 0.35
HTTP_TIMEOUT = 0.8
CHUNK = 2048

_LOCK = threading.Lock()
_CACHE: dict[str, dict[int, dict]] = {}
_CACHE_TIME: dict[str, float] = {}
_STATE = {
    "enabled": ENABLED,
    "running": False,
    "started": 0.0,
    "finished": 0.0,
    "hosts": {},
    "error": "",
}


def _valid_port(port: int) -> bool:
    return isinstance(port, int) and 1 <= port <= 65535


def _private_address(host: str) -> str | None:
    """Resolve ``host`` and return its IPv4 only when it is not public."""
    try:
        address = socket.gethostbyname(host)
        parsed = ipaddress.ip_address(address)
    except (OSError, ValueError):
        return None
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        return None
    if not (parsed.is_private or parsed.is_link_local):
        return None
    return address


def _chunks(values: list[int], size: int):
    for index in range(0, len(values), size):
        yield values[index:index + size]


async def _probe(ip: str, port: int, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT
            )
            del reader
            return port
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, Exception):  # noqa: BLE001 - close must never fail the scan
                    pass


def _scan_ports(ip: str, ports: list[int]) -> list[int]:
    if not ports:
        return []
    open_ports: list[int] = []

    async def run() -> None:
        sem = asyncio.Semaphore(CONCURRENCY)
        for chunk in _chunks(ports, CHUNK):
            results = await asyncio.gather(*(_probe(ip, port, sem) for port in chunk))
            open_ports.extend(port for port in results if port is not None)

    try:
        asyncio.run(run())
    except RuntimeError:
        # An event loop may already be running in the caller (tests, Flask
        # workers). Fall back to blocking sockets in a small thread pool.
        open_ports.extend(_scan_ports_threads(ip, ports))
    return sorted(set(open_ports))


def _scan_ports_threads(ip: str, ports: list[int]) -> list[int]:
    def probe(port: int) -> int | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            return port if sock.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=256) as pool:
        return [port for port in pool.map(probe, ports) if port is not None]


def _http_probe(ip: str, port: int) -> dict:
    """Return ``{"http": bool, "prometheus": bool}`` for one TCP port."""
    if port < 1024 and port not in {80, 443}:
        return {"http": False, "prometheus": False}
    request = (
        b"GET / HTTP/1.0\r\n"
        b"Host: umbrel-tunnel\r\n"
        b"User-Agent: umbrel-tunnel/port-scan\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((ip, port), timeout=HTTP_TIMEOUT) as sock:
            sock.sendall(request)
            data = sock.recv(1024)
    except OSError:
        data = b""
    if data.startswith(b"HTTP/"):
        body = data.lower()
        return {"http": True, "prometheus": b"# help" in body or b"# type" in body}
    # Some web services only speak TLS. Try a throw-away handshake; the
    # certificate is deliberately not verified because this is not a trust
    # decision, only a protocol hint.
    try:
        context = ssl._create_unverified_context()  # noqa: SLF001 - probe only
        with socket.create_connection((ip, port), timeout=HTTP_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: umbrel-tunnel\r\n"
                    b"Connection: close\r\n\r\n"
                )
                data = tls.recv(1024)
    except (OSError, ssl.SSLError):
        return {"http": False, "prometheus": False}
    if data.startswith(b"HTTP/"):
        return {"http": True, "prometheus": False}
    return {"http": False, "prometheus": False}


def _scan_host(host: str, priority_ports: set[int]) -> dict[int, dict]:
    ip = _private_address(host)
    if not ip:
        return {}
    result: dict[int, dict] = {}

    def collect(ports: list[int]) -> None:
        opened = _scan_ports(ip, ports)
        for port in opened:
            result[port] = _http_probe(ip, port)
        with _LOCK:
            _CACHE[host] = dict(result)

    first = {port for port in priority_ports if _valid_port(port)}
    first.update(range(1, PRIORITY_MAX + 1))
    collect(sorted(first))
    if FULL_SCAN:
        rest = [port for port in range(PRIORITY_MAX + 1, 65536) if port not in first]
        if rest:
            collect(rest)
    return result


def _run(hosts: list[str], priority_ports: set[int]) -> None:
    try:
        for host in hosts:
            with _LOCK:
                _STATE["hosts"][host] = "scanning"
            result = _scan_host(host, priority_ports)
            with _LOCK:
                _CACHE[host] = dict(result)
                _CACHE_TIME[host] = time.time()
                _STATE["hosts"][host] = "done"
    except Exception as exc:  # noqa: BLE001 - the scan must never break detection
        with _LOCK:
            _STATE["error"] = str(exc)
    finally:
        with _LOCK:
            _STATE["running"] = False
            _STATE["finished"] = time.time()


def ensure(hosts: list[str], priority_ports: set[int] | None = None, force: bool = False) -> bool:
    """Start a background scan when needed. Returns True when one was started."""
    if not ENABLED:
        return False
    cleaned = sorted({str(host).strip() for host in hosts if str(host).strip()})
    if not cleaned:
        return False
    with _LOCK:
        if _STATE["running"]:
            return False
        now = time.time()
        pending = [
            host
            for host in cleaned
            if force or host not in _CACHE or now - _CACHE_TIME.get(host, 0.0) >= TTL
        ]
        if not pending:
            return False
        _STATE["running"] = True
        _STATE["started"] = now
        _STATE["finished"] = 0.0
        _STATE["error"] = ""
        _STATE["hosts"] = {host: "pending" for host in pending}
    thread = threading.Thread(
        target=_run,
        args=(pending, set(priority_ports or set())),
        name="umbrel-tunnel-port-scan",
        daemon=True,
    )
    thread.start()
    return True


def snapshot() -> dict[str, dict[int, dict]]:
    with _LOCK:
        return {host: dict(ports) for host, ports in _CACHE.items()}


def ports_for(host: str) -> dict[int, dict]:
    with _LOCK:
        return dict(_CACHE.get(host) or {})


def status() -> dict:
    with _LOCK:
        return {
            "enabled": _STATE["enabled"],
            "running": _STATE["running"],
            "started": _STATE["started"],
            "finished": _STATE["finished"],
            "hosts": dict(_STATE["hosts"]),
            "error": _STATE["error"],
            "cached_hosts": sorted(_CACHE),
        }


def reset() -> None:
    """Clear the cache. Used by tests and by an explicit refresh."""
    with _LOCK:
        _CACHE.clear()
        _CACHE_TIME.clear()
        _STATE.update(
            {
                "running": False,
                "started": 0.0,
                "finished": 0.0,
                "hosts": {},
                "error": "",
            }
        )


def invalidate() -> None:
    """Drop cached ports so the next detection scans again.

    Unlike :func:`reset` this leaves a running scan alone: it keeps writing its
    results and the following detection will pick them up.
    """
    with _LOCK:
        _CACHE.clear()
        _CACHE_TIME.clear()


def scan_host_now(host: str) -> dict[int, dict]:
    """Synchronous scan for tests and explicit diagnostics."""
    result = _scan_host(host, set())
    with _LOCK:
        _CACHE[host] = dict(result)
        _CACHE_TIME[host] = time.time()
    return result

"""External port checks that explain certificate failures.

The VPS can only see its own interfaces: a provider firewall or an upstream
filter looks open from there. The Umbrel box sits on a different network, so a
TCP connect from here tests the same path Let's Encrypt uses. Results are cached
because the UI polls the certificate list every few seconds.
"""

from __future__ import annotations

import concurrent.futures
import socket
import time

PORTS = (80, 443)
TTL = 300
TIMEOUT = 1.5

_cache: dict[tuple[str, tuple[int, ...]], tuple[float, dict[str, bool]]] = {}


def _probe(domain: str, port: int, timeout: float = TIMEOUT) -> bool:
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return True
    except OSError:
        return False


def check(domain: str, ports: tuple[int, ...] = PORTS, ttl: int = TTL) -> dict[str, bool]:
    """Return {port: reachable} from this host, cached for a few minutes."""
    key = (domain, tuple(ports))
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and now - cached[0] < ttl:
        return dict(cached[1])
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as pool:
        futures = {port: pool.submit(_probe, domain, port) for port in ports}
        result = {str(port): bool(future.result()) for port, future in futures.items()}
    _cache[key] = (now, result)
    return dict(result)


def clear() -> None:
    """Drop cached results; used by tests and after a manual retry."""
    _cache.clear()

"""Validación de destinos y fijado de DNS para servicios publicados.

La app publica servicios internos de Umbrel. Un destino nunca debe apuntar a
loopback, link-local (metadatos cloud), multicast ni direcciones reservadas:
publicarlas expondría el propio gateway o servicios del host que no forman
parte del túnel.

La validación es deliberadamente conservadora para no romper servicios
legítimos:

- Las direcciones privadas (10/8, 172.16/12, 192.168/16) se permiten.
- Los nombres DNS de contenedores Docker se permiten.
- Si un nombre no resuelve todavía, se acepta al guardarlo: el contenedor puede
  arrancar después. Al conectar sí se exige una IP aprobada.

Anti-rebinding: cada sincronización vuelve a resolver el destino y rechaza la
publicación si ahora apunta a una red bloqueada. El relay UDP fija la IP
aprobada al abrir la sesión, de modo que una segunda resolución no puede
desviar el tráfico a loopback.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time

# Rangos que nunca deben ser alcanzables desde una publicación pública.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",   # CGNAT; incluye 100.100.100.200 (metadatos cloud)
        "192.0.0.0/24",    # protocolos IETF
        "198.18.0.0/15",   # benchmarking
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    )
)

_PIN_TTL = max(5.0, float(os.environ.get("UMBREL_TUNNEL_TARGET_DNS_TTL", "30") or 30))
_PIN_LOCK = threading.Lock()
_PINNED: dict[str, tuple[float, tuple[str, ...]]] = {}


class TargetError(ValueError):
    """El destino no se puede publicar."""


def _normalize(host: str) -> str:
    value = str(host or "").strip()
    if not value:
        raise TargetError("empty_host")
    if any(ord(char) < 32 for char in value):
        raise TargetError("invalid_host")
    if "/" in value or "\\" in value or "@" in value:
        raise TargetError("invalid_host")
    # Un IPv6 literal puede venir entre corchetes desde una URL.
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    # ::ffff:127.0.0.1 debe evaluarse como la IPv4 que representa.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in _BLOCKED_NETWORKS)


def is_ip_literal(host: str) -> bool:
    try:
        return _parse_ip(_normalize(host)) is not None
    except TargetError:
        return False


def is_external_name(host: str) -> bool:
    """Un nombre DNS externo (no IP, no nombre de contenedor Docker)."""
    try:
        value = _normalize(host)
    except TargetError:
        return False
    return _parse_ip(value) is None and "." in value


def _resolved_addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resuelve un nombre, sin convertirlo en un requisito.

    Docker DNS resuelve los nombres de contenedor. Si el nombre todavía no
    existe (la app está parada), no hay direcciones que validar y se acepta.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        candidate = info[4][0]
        address = _parse_ip(str(candidate))
        if address is not None and address not in addresses:
            addresses.append(address)
    return addresses


def validate(host: str) -> str:
    """Devuelve el host normalizado o lanza ``TargetError``.

    Resuelve de nuevo en cada llamada: la sincronización periódica revalida los
    destinos y corta un rebinding que aparezca después de guardarlos.

    No comprueba puertos: muchos servicios legítimos usan 8080/8443 y bloquear
    por número rompería publicaciones que hoy funcionan.
    """
    value = _normalize(host)
    literal = _parse_ip(value)
    if literal is not None:
        if _is_blocked(literal):
            raise TargetError("blocked_target")
        return value

    # Un host con espacios o caracteres no válidos no es un nombre DNS.
    if any(char.isspace() for char in value):
        raise TargetError("invalid_host")

    for address in _resolved_addresses(value):
        if _is_blocked(address):
            raise TargetError("blocked_target")
    return value


def pin(host: str, refresh: bool = False) -> str:
    """Valida ``host`` y fija una IPv4 aprobada durante ``_PIN_TTL`` segundos.

    Se usa al abrir una sesión UDP: la conexión posterior no vuelve a resolver,
    así que un DNS que cambie a mitad de sesión no puede redirigir el tráfico.
    """
    value = _normalize(host)
    now = time.monotonic()
    if not refresh:
        with _PIN_LOCK:
            cached = _PINNED.get(value)
            if cached and cached[0] > now and cached[1]:
                return cached[1][0]

    # Sin una IP fijada vigente, valida de nuevo antes de aceptar el nombre.
    validate(value)
    literal = _parse_ip(value)
    if literal is not None:
        addresses = [literal]
    else:
        addresses = [a for a in _resolved_addresses(value) if isinstance(a, ipaddress.IPv4Address)]
    if not addresses:
        raise TargetError("unresolved_target")

    # Revalida por si la resolución cambió entre validate() y esta llamada.
    for address in addresses:
        if _is_blocked(address):
            raise TargetError("blocked_target")

    texts = tuple(str(a) for a in addresses)
    with _PIN_LOCK:
        _PINNED[value] = (now + _PIN_TTL, texts)
    return texts[0]


def clear_cache() -> None:
    with _PIN_LOCK:
        _PINNED.clear()

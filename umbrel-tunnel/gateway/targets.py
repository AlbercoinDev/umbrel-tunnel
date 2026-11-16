"""Validación de destinos para servicios manuales.

La app publica servicios internos de Umbrel. Un destino manual nunca debe
apuntar a loopback, link-local (metadatos cloud), multicast ni direcciones
reservadas: publicarlas expondría el propio gateway o servicios del host que no
forman parte del túnel.

La validación es deliberadamente conservadora para no romper servicios
legítimos:

- Las direcciones privadas (10/8, 172.16/12, 192.168/16) se permiten.
- Los nombres DNS de contenedores Docker se permiten.
- Si un nombre no resuelve todavía, se acepta: el contenedor puede arrancar
  después. La comprobación de literales IP siempre se aplica.
"""

from __future__ import annotations

import ipaddress
import socket


class TargetError(ValueError):
    """El destino no se puede publicar."""


# Rangos que nunca deben ser alcanzables desde una publicación pública.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    )
)


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

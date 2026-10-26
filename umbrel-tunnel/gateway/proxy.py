"""Proxy TCP local: escucha en la IP del túnel y reenvía a la app real.

El VPS hace DNAT del puerto público a ``<umbrel_ip>:<tunnel_port>``. HAProxy
escucha ese puerto en ``wg0`` y conecta con el contenedor de la app por su
nombre DNS de Docker. Las IPs de contenedor cambian al reiniciar, así que los
backends se resuelven dinámicamente con el resolver interno de Docker.
"""

from __future__ import annotations

import ipaddress
import os
import re
import signal
import subprocess
import time
from pathlib import Path

DATA_DIR = Path(os.environ.get("UMBREL_TUNNEL_DATA", "/data"))
DATA_CFG = DATA_DIR / "haproxy.cfg"
ETC_CFG = Path(os.environ.get("UMBREL_TUNNEL_HAPROXY_CONF", "/etc/haproxy/haproxy.cfg"))
PID_FILE = Path(os.environ.get("UMBREL_TUNNEL_HAPROXY_PID", "/var/run/haproxy.pid"))
BIND_IP = "10.0.0.2"
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


class ProxyError(RuntimeError):
    pass


def _safe(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    return cleaned[:40] or fallback


def _valid_bind_ip(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise ProxyError(f"IP de escucha inválida: {value!r}") from exc


def _valid_target(host: str, port: int) -> tuple[str, int]:
    host = (host or "").strip()
    if not HOST_RE.match(host):
        raise ProxyError(f"destino inválido: {host!r}")
    if not (1 <= int(port) <= 65535):
        raise ProxyError(f"puerto destino inválido: {port}")
    return host, int(port)


def render(forwards: list[dict], bind_ip: str = BIND_IP) -> str:
    bind_ip = _valid_bind_ip(bind_ip)
    lines = [
        "global",
        "    daemon",
        "    maxconn 512",
        "    stats socket /var/run/haproxy.sock mode 600",
        "",
        "defaults",
        "    mode tcp",
        "    timeout connect 5s",
        "    timeout client 1m",
        "    timeout server 1m",
        "    option tcplog",
        "",
        "resolvers docker",
        "    nameserver dns 127.0.0.11:53",
        "    resolve_retries 3",
        "    timeout resolve 1s",
        "    timeout retry 1s",
        "    hold valid 10s",
        "",
    ]
    for fwd in forwards:
        if not fwd.get("enabled", True):
            continue
        name = _safe(fwd.get("name") or fwd.get("id", ""), "fwd")
        unique = _safe(fwd.get("id", ""), "0")[:8]
        backend = f"b_{name}_{unique}"
        try:
            tunnel_port = int(fwd["tunnel_port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProxyError(f"puerto del túnel inválido en {name}") from exc
        if not (1 <= tunnel_port <= 65535):
            raise ProxyError(f"puerto del túnel fuera de rango en {name}")
        host, port = _valid_target(str(fwd.get("target_ip") or ""), int(fwd.get("target_port") or 0))
        lines += [
            f"frontend f_{name}_{unique}",
            f"    bind {bind_ip}:{tunnel_port}",
            f"    default_backend {backend}",
            "",
            f"backend {backend}",
            f"    server s1 {host}:{port} check inter 10s fall 3 rise 2 "
            "resolvers docker resolve-prefer ipv4 init-addr last,libc,none",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop() -> None:
    pid = _read_pid()
    if pid and _alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    try:
        PID_FILE.unlink()
    except OSError:
        pass


def _run(args: list[str], timeout: float = 15.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProxyError(f"no se pudo ejecutar {' '.join(args)}: {exc}") from exc


def apply(forwards: list[dict], bind_ip: str = BIND_IP) -> str:
    enabled = [f for f in forwards if f.get("enabled", True)]
    if not enabled:
        stop()
        return "sin puertos que proxyar"

    config = render(enabled, bind_ip)
    DATA_CFG.parent.mkdir(parents=True, exist_ok=True)
    DATA_CFG.write_text(config, encoding="utf-8")

    # Validate a temporary file first so a bad rule never replaces a working
    # HAProxy configuration.
    ETC_CFG.parent.mkdir(parents=True, exist_ok=True)
    candidate = ETC_CFG.with_suffix(".candidate")
    candidate.write_text(config, encoding="utf-8")
    check = _run(["haproxy", "-c", "-f", str(candidate)])
    if check.returncode != 0:
        detail = (check.stderr or check.stdout or "").strip()
        try:
            candidate.unlink()
        except OSError:
            pass
        raise ProxyError(f"configuración de HAProxy inválida: {detail}")
    os.replace(candidate, ETC_CFG)

    old_pid = _read_pid()
    args = ["haproxy", "-f", str(ETC_CFG), "-p", str(PID_FILE)]
    if old_pid and _alive(old_pid):
        args += ["-sf", str(old_pid)]
    result = _run(args)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ProxyError(f"no se pudo arrancar HAProxy: {detail}")
    time.sleep(0.2)
    new_pid = _read_pid()
    if not new_pid or not _alive(new_pid):
        raise ProxyError("HAProxy no quedó en ejecución")
    return f"{len(enabled)} puerto(s) proxyados"

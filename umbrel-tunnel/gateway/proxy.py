"""Proxy TCP local: escucha en la IP del túnel y reenvía a la app real.

El VPS hace DNAT del puerto público a 10.0.0.2:<tunnel_port>. Aquí HAProxy
escucha ese puerto en wg0 y conecta con el contenedor de la app a través de la
red compartida de Umbrel.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
from pathlib import Path

DATA_CFG = Path("/data/haproxy.cfg")
ETC_CFG = Path("/etc/haproxy/haproxy.cfg")
PID_FILE = Path("/var/run/haproxy.pid")
BIND_IP = "10.0.0.2"


class ProxyError(RuntimeError):
    pass


def _safe(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    return cleaned[:40] or fallback


def render(forwards: list[dict], bind_ip: str = BIND_IP) -> str:
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
    ]
    for fwd in forwards:
        if not fwd.get("enabled", True):
            continue
        name = _safe(fwd.get("name") or fwd.get("id", ""), "fwd")
        unique = _safe(fwd.get("id", ""), "0")[:8]
        backend = f"b_{name}_{unique}"
        lines += [
            f"frontend f_{name}_{unique}",
            f"    bind {bind_ip}:{int(fwd['tunnel_port'])}",
            f"    default_backend {backend}",
            "",
            f"backend {backend}",
            f"    server s1 {fwd['target_ip']}:{int(fwd['target_port'])} check inter 10s fall 3 rise 2",
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
    ETC_CFG.parent.mkdir(parents=True, exist_ok=True)
    DATA_CFG.write_text(config, encoding="utf-8")
    ETC_CFG.write_text(config, encoding="utf-8")

    check = _run(["haproxy", "-c", "-f", str(ETC_CFG)])
    if check.returncode != 0:
        detail = (check.stderr or check.stdout or "").strip()
        raise ProxyError(f"configuración de HAProxy inválida: {detail}")

    old_pid = _read_pid()
    args = ["haproxy", "-f", str(ETC_CFG), "-p", str(PID_FILE)]
    if old_pid and _alive(old_pid):
        args += ["-sf", str(old_pid)]
    result = _run(args)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ProxyError(f"no se pudo arrancar HAProxy: {detail}")
    return f"{len(enabled)} puerto(s) proxyados"

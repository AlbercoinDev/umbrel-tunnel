"""Salud real de las publicaciones, sin bloquear las peticiones del panel.

Cada ciclo abre una conexión TCP al destino real desde el gateway y, en
publicaciones web, comprueba que el destino responde HTTP. El resultado vive
solo en memoria: no se reescribe ``config.json`` cada minuto.

- TCP: estado ``ok`` o ``fail`` con latencia.
- HTTP/HTTPS: la respuesta HTTP es informativa; si el TCP funciona pero el
  destino no habla HTTP, la publicación sigue ``ok``.
- UDP: ``unknown``; no existe una sonda fiable sin conocer el protocolo.
- Pausadas: ``paused``. Con error de sincronización: ``fail`` sin sondear.
"""

from __future__ import annotations

import http.client
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ENABLED = os.environ.get("UMBREL_TUNNEL_HEALTH", "1") != "0"
INTERVAL = max(15, int(os.environ.get("UMBREL_TUNNEL_HEALTH_INTERVAL", "30") or 60))
TIMEOUT = max(0.5, float(os.environ.get("UMBREL_TUNNEL_HEALTH_TIMEOUT", "2.5") or 2.5))
WORKERS = 4

_LOCK = threading.RLock()
_CACHE: dict[str, dict] = {}
_STOP = threading.Event()
_STATE = {"running": False, "started": 0.0, "finished": 0.0, "error": ""}


def _result(state: str, detail: str = "", latency_ms: int | None = None) -> dict:
    return {
        "state": state,
        "detail": detail,
        "latency_ms": latency_ms,
        "checked_at": time.time(),
    }


def _tcp(host: str, port: int) -> tuple[bool, int | None, str]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            pass
    except OSError as exc:
        return False, None, str(exc)
    return True, int((time.monotonic() - start) * 1000), ""


def _http(host: str, port: int) -> tuple[bool, str]:
    """Cualquier respuesta HTTP cuenta; 401/404 también demuestran que vive."""
    try:
        connection = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
        try:
            connection.request("HEAD", "/", headers={"User-Agent": "umbrel-tunnel-health"})
            connection.getresponse().read(0)
            return True, ""
        finally:
            connection.close()
    except (OSError, http.client.HTTPException) as exc:
        return False, str(exc)


def check(exposure: dict) -> dict:
    if not exposure.get("enabled", True):
        return _result("paused")
    if exposure.get("sync_error"):
        return _result("fail", "sin forward en el VPS")
    protocol = str(exposure.get("protocol") or "tcp").lower()
    if protocol == "udp":
        return _result("unknown", "UDP no tiene sonda fiable")
    host = str(exposure.get("target_ip") or "").strip()
    try:
        port = int(exposure.get("target_port") or 0)
    except (TypeError, ValueError):
        return _result("fail", "puerto de destino inválido")
    if not host or not (1 <= port <= 65535):
        return _result("fail", "destino incompleto")

    ok, latency, error = _tcp(host, port)
    if not ok:
        return _result("fail", error or "no responde")

    detail = ""
    if str(exposure.get("access_mode") or "direct") in {"http", "https"}:
        speaks_http, http_error = _http(host, port)
        if not speaks_http:
            # El TCP está abierto: puede ser un servicio no HTTP. No lo
            # marcamos caído por eso, pero dejamos el detalle.
            detail = f"HTTP: {http_error}" if http_error else ""
    return _result("ok", detail, latency)


def run_once() -> None:
    try:
        import state

        config = state.load()
    except Exception as exc:  # noqa: BLE001 - la salud nunca tumba el gateway
        with _LOCK:
            _STATE["error"] = str(exc)
        return
    exposures = [e for e in (config.get("exposures") or []) if e.get("id")]
    results: dict[str, dict] = {}
    if exposures:
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(exposures))) as pool:
            futures = {str(e["id"]): pool.submit(check, e) for e in exposures}
            for exposure_id, future in futures.items():
                try:
                    results[exposure_id] = future.result()
                except Exception as exc:  # noqa: BLE001
                    results[exposure_id] = _result("unknown", str(exc))
    now = time.time()
    with _LOCK:
        _CACHE.clear()
        _CACHE.update(results)
        _STATE.update({"running": False, "finished": now, "error": ""})


def run_forever() -> None:
    if not ENABLED:
        return
    with _LOCK:
        _STATE["running"] = True
        _STATE["started"] = time.time()
    while not _STOP.is_set():
        run_once()
        if _STOP.wait(INTERVAL):
            break
    with _LOCK:
        _STATE["running"] = False


def start() -> threading.Thread | None:
    if not ENABLED:
        return None
    thread = threading.Thread(target=run_forever, name="health", daemon=True)
    thread.start()
    return thread


def stop() -> None:
    _STOP.set()


def snapshot() -> dict[str, dict]:
    with _LOCK:
        return {key: dict(value) for key, value in _CACHE.items()}


def summary(config: dict) -> dict:
    """Recuento para /api/status y el widget. Sin datos no inventa un 0."""
    health = snapshot()
    enabled = [e for e in (config.get("exposures") or []) if e.get("enabled", True)]
    states = [str((health.get(str(e.get("id"))) or {}).get("state") or "unknown") for e in enabled]
    return {
        "total": len(enabled),
        "ok": states.count("ok"),
        "fail": states.count("fail"),
        "unknown": states.count("unknown"),
        "checked_at": max((value.get("checked_at") or 0) for value in health.values()) if health else 0,
        "enabled": ENABLED,
    }


def state() -> dict:
    with _LOCK:
        return dict(_STATE)

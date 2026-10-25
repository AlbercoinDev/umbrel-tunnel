"""tunnel-wg - gateway de Umbrel.

Expone servicios de Umbrel a través de un VPS con WireGuard. La app detecta
contenedores y servicios, deja elegir qué puertos abrir y sincroniza los
forwards con la API del VPS.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.parse
import uuid

from flask import Flask, jsonify, render_template, request

import detect
import proxy
import state
import sync
import wireguard
from vps import VPSClient, VPSError

VERSION = os.environ.get("APP_VERSION", "1.0.0")
RESERVED_PUBLIC_PORTS = {22}

app = Flask(__name__, static_folder="static", template_folder="templates")
STARTED = time.time()

_detect_lock = threading.Lock()
_detect_cache: dict = {"at": 0.0, "services": []}
_sync_lock = threading.Lock()
_last_sync: dict = {"ok": False, "errors": ["sin sincronizar"], "at": 0}


def detect_cached(force: bool = False) -> list[dict]:
    now = time.time()
    with _detect_lock:
        if force or now - _detect_cache["at"] > 15:
            _detect_cache["services"] = detect.detect_services()
            _detect_cache["at"] = now
        return list(_detect_cache["services"])


def sync_now() -> dict:
    global _last_sync
    with _sync_lock:
        with state.LOCK:
            config = state.load()
            try:
                result = sync.sync(config)
            except Exception as exc:  # noqa: BLE001 - se devuelve al usuario
                result = {
                    "ok": False,
                    "created": 0,
                    "updated": 0,
                    "deleted": 0,
                    "errors": [f"error inesperado: {exc}"],
                    "vps_status": None,
                    "at": time.time(),
                }
            state.save(config)
            _last_sync = result
            return result


def decode_pair(code: str) -> dict:
    code = (code or "").strip()
    if not code.startswith("tw1."):
        raise ValueError("el código debe empezar por tw1.")
    raw = code[4:]
    padded = raw + "=" * ((4 - len(raw) % 4) % 4)
    try:
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(data)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"código de emparejamiento inválido: {exc}") from exc
    if payload.get("v") != 1:
        raise ValueError("versión de emparejamiento no soportada")
    api = str(payload.get("api") or "")
    parsed = urllib.parse.urlparse(api)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("el código contiene una API inválida")
    if not str(payload.get("token") or "").strip():
        raise ValueError("el código no contiene token")
    return payload


def validate_public_port(port: int) -> None:
    if not (1 <= port <= 65535):
        raise ValueError("el puerto público debe estar entre 1 y 65535")
    if port in RESERVED_PUBLIC_PORTS:
        raise ValueError("el puerto 22 es el SSH del VPS; elige otro (por ejemplo 2222)")


def allocate_tunnel_port(config: dict) -> int:
    used = {int(e.get("tunnel_port", 0)) for e in config.get("exposures", [])}
    settings = config.get("settings") or {}
    start = int(settings.get("tunnel_port_start", 20000))
    end = int(settings.get("tunnel_port_end", 29999))
    for port in range(start, end + 1):
        if port not in used:
            return port
    raise ValueError("no quedan puertos internos libres")


def public_port_in_use(config: dict, port: int, ignore_id: str | None = None) -> bool:
    for exposure in config.get("exposures", []):
        if exposure.get("id") == ignore_id:
            continue
        if int(exposure.get("public_port", 0)) == port:
            return True
    return False


def service_by_id(service_id: str) -> dict | None:
    for svc in detect_cached():
        if svc["id"] == service_id:
            return svc
    return None


def exposure_view(exposure: dict) -> dict:
    return {
        **exposure,
        "vps_name": sync.vps_name(exposure),
        "sync_ok": not exposure.get("sync_error"),
    }


@app.get("/")
def index():
    return render_template("index.html", version=VERSION)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "version": VERSION})


@app.get("/api/status")
def status():
    config = state.load()
    wg = wireguard.status()
    return jsonify(
        {
            "version": VERSION,
            "uptime": int(time.time() - STARTED),
            "paired": state.paired(config),
            "vps": {
                "api": (config.get("vps") or {}).get("api", ""),
                "endpoint": (config.get("vps") or {}).get("endpoint", ""),
                "server_pubkey": (config.get("vps") or {}).get("server_pubkey", ""),
            },
            "wg": wg,
            "exposures": len(config.get("exposures", [])),
            "exposures_enabled": sum(1 for e in config.get("exposures", []) if e.get("enabled", True)),
            "services": len(detect_cached()),
            "last_sync": _last_sync,
        }
    )


@app.get("/api/services")
def services():
    config = state.load()
    by_service = {
        (e.get("service_id"), e.get("target_port")): e
        for e in config.get("exposures", [])
    }
    result = []
    for svc in detect_cached():
        item = dict(svc)
        exposure = by_service.get((svc["id"], svc["target_port"]))
        item["exposed"] = exposure is not None
        item["exposure_enabled"] = bool(exposure.get("enabled", True)) if exposure else False
        item["default_public_port"] = 2222 if svc["target_port"] == 22 else svc["target_port"]
        result.append(item)
    return jsonify(result)


@app.post("/api/services/refresh")
def refresh_services():
    return jsonify(detect_cached(force=True))


@app.get("/api/exposures")
def list_exposures():
    config = state.load()
    return jsonify([exposure_view(e) for e in config.get("exposures", [])])


@app.post("/api/exposures")
def create_exposure():
    body = request.get_json(silent=True) or {}
    service = service_by_id(str(body.get("service_id") or ""))
    if not service:
        return jsonify({"error": "servicio no encontrado; refresca la lista"}), 404

    try:
        public_port = int(body.get("public_port") or service["target_port"])
    except (TypeError, ValueError):
        return jsonify({"error": "puerto público inválido"}), 400
    try:
        validate_public_port(public_port)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    with state.LOCK:
        config = state.load()
        if public_port_in_use(config, public_port):
            return jsonify({"error": f"el puerto público {public_port} ya está asignado"}), 409
        exposure = {
            "id": uuid.uuid4().hex[:12],
            "service_id": service["id"],
            "name": body.get("name") or f"{service['app']} - {service['name']}",
            "app": service["app"],
            "service": service["name"],
            "target_ip": service["target_ip"],
            "target_port": service["target_port"],
            "tunnel_ip": (config.get("vps") or {}).get("umbrel_ip") or "10.0.0.2",
            "public_port": public_port,
            "tunnel_port": allocate_tunnel_port(config),
            "protocol": "tcp",
            "enabled": True,
            "sensitive": service["sensitive"],
            "vps_forward_id": None,
            "vps_name": "",
            "sync_error": "",
            "last_sync": 0,
        }
        config.setdefault("exposures", []).append(exposure)
        state.save(config)

    result = sync_now()
    current = state.load()
    saved = state.find_exposure(current, exposure["id"])
    return jsonify({"exposure": exposure_view(saved or exposure), "sync": result}), 201


@app.patch("/api/exposures/<exposure_id>")
def update_exposure(exposure_id: str):
    body = request.get_json(silent=True) or {}
    with state.LOCK:
        config = state.load()
        exposure = state.find_exposure(config, exposure_id)
        if not exposure:
            return jsonify({"error": "exposición no encontrada"}), 404

        if "public_port" in body:
            try:
                public_port = int(body["public_port"])
                validate_public_port(public_port)
            except (TypeError, ValueError) as exc:
                return jsonify({"error": str(exc)}), 400
            if public_port_in_use(config, public_port, ignore_id=exposure_id):
                return jsonify({"error": f"el puerto público {public_port} ya está asignado"}), 409
            exposure["public_port"] = public_port
        if "enabled" in body:
            exposure["enabled"] = bool(body["enabled"])
        if "name" in body and str(body["name"]).strip():
            exposure["name"] = str(body["name"]).strip()[:80]
        exposure["vps_name"] = sync.vps_name(exposure)
        state.save(config)

    result = sync_now()
    current = state.load()
    saved = state.find_exposure(current, exposure_id)
    return jsonify({"exposure": exposure_view(saved or {}), "sync": result})


@app.delete("/api/exposures/<exposure_id>")
def delete_exposure(exposure_id: str):
    with state.LOCK:
        config = state.load()
        exposure = state.find_exposure(config, exposure_id)
        if not exposure:
            return jsonify({"error": "exposición no encontrada"}), 404
        forward_id = exposure.get("vps_forward_id")
        if forward_id and state.paired(config):
            vps = config.get("vps") or {}
            try:
                VPSClient(vps["api"], vps["token"]).delete_forward(forward_id)
            except VPSError as exc:
                return jsonify({"error": f"no se pudo cerrar el puerto en el VPS: {exc}"}), 502
        config["exposures"] = [e for e in config["exposures"] if e.get("id") != exposure_id]
        state.save(config)

    result = sync_now()
    return jsonify({"ok": True, "sync": result})


@app.post("/api/sync")
def sync_route():
    return jsonify(sync_now())


@app.post("/api/pair")
def pair():
    body = request.get_json(silent=True) or {}
    try:
        payload = decode_pair(str(body.get("code") or ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    api = str(payload["api"]).rstrip("/")
    token = str(payload["token"]).strip()
    with state.LOCK:
        config = state.load()
        config["vps"] = {
            "api": api,
            "token": token,
            "endpoint": str(payload.get("endpoint") or ""),
            "server_pubkey": str(payload.get("server_pubkey") or ""),
            "umbrel_ip": str(payload.get("umbrel_ip") or "10.0.0.2"),
        }
        state.save(config)

    if not payload.get("wg"):
        # Manual pairing: the VPS does not know our public key yet, so the
        # tunnel cannot work until the user completes the manual form.
        return jsonify(
            {
                "ok": False,
                "paired": True,
                "manual": True,
                "wg": "emparejamiento guardado. Ahora configura WireGuard en la pestaña Conexión.",
                "sync": {
                    "ok": False,
                    "errors": ["WireGuard aún no configurado"],
                    "at": time.time(),
                },
            }
        )

    try:
        wireguard.save_config(str(payload["wg"]))
        wg_ok, wg_message = wireguard.apply_saved()
    except wireguard.WireGuardError as exc:
        return jsonify({"error": f"configuración de WireGuard inválida: {exc}"}), 400

    try:
        vps_status = VPSClient(api, token).status()
    except VPSError as exc:
        return (
            jsonify(
                {
                    "error": f"emparejamiento guardado, pero la API del VPS no responde: {exc}",
                    "paired": True,
                    "wg": wg_message,
                }
            ),
            502,
        )

    result = sync_now() if wg_ok else {"ok": False, "errors": [wg_message], "at": time.time()}
    return jsonify(
        {
            "ok": wg_ok,
            "paired": True,
            "wg": wg_message,
            "vps": {
                "version": vps_status.get("version"),
                "peers_connected": vps_status.get("peers_connected"),
            },
            "sync": result,
        }
    )


@app.post("/api/unpair")
def unpair():
    with state.LOCK:
        config = state.load()
        sync.remove_all(config)
        config["vps"] = {}
        for exposure in config.get("exposures", []):
            exposure["vps_forward_id"] = None
            exposure["sync_error"] = ""
        state.save(config)
    proxy.stop()
    wireguard.remove()
    return jsonify({"ok": True})


@app.get("/api/wireguard")
def get_wireguard():
    return jsonify(
        {
            "config": wireguard.config_text(),
            "status": wireguard.status(),
            "address": wireguard.address(),
        }
    )


@app.post("/api/wireguard/manual")
def manual_wireguard():
    body = request.get_json(silent=True) or {}
    config = state.load()
    vps = config.get("vps") or {}
    endpoint = str(body.get("endpoint") or vps.get("endpoint") or "")
    server_pubkey = str(body.get("server_pubkey") or vps.get("server_pubkey") or "")
    client_ip = str(body.get("client_ip") or vps.get("umbrel_ip") or "10.0.0.2")
    if not endpoint or not server_pubkey:
        return jsonify({"error": "faltan endpoint y clave pública del servidor"}), 400
    if ":" not in endpoint:
        endpoint = f"{endpoint}:51820"

    try:
        private, public = wireguard.generate_keypair()
        text = wireguard.build_config(private, client_ip, server_pubkey, endpoint)
        wireguard.save_config(text)
        ok, message = wireguard.apply_saved()
    except wireguard.WireGuardError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(
        {
            "public_key": public,
            "config": text,
            "applied": ok,
            "message": message,
            "instructions": (
                "Añade esta clave pública al VPS: "
                f"tunnel-wg peer add --name umbrel --ip {client_ip} --pubkey {public}"
            ),
        }
    )


@app.post("/api/wireguard/apply")
def apply_wireguard():
    body = request.get_json(silent=True) or {}
    text = str(body.get("config") or "")
    try:
        wireguard.save_config(text)
        ok, message = wireguard.apply_saved()
    except wireguard.WireGuardError as exc:
        return jsonify({"error": str(exc)}), 400
    result = sync_now() if ok else {"ok": False, "errors": [message], "at": time.time()}
    return jsonify({"ok": ok, "message": message, "sync": result})


@app.get("/api/settings")
def get_settings():
    config = state.load()
    vps = config.get("vps") or {}
    return jsonify(
        {
            "api": vps.get("api", ""),
            "token_set": bool(vps.get("token")),
            "endpoint": vps.get("endpoint", ""),
            "settings": config.get("settings", {}),
        }
    )


@app.post("/api/settings")
def update_settings():
    body = request.get_json(silent=True) or {}
    with state.LOCK:
        config = state.load()
        vps = config.setdefault("vps", {})
        if "api" in body:
            api = str(body["api"]).strip().rstrip("/")
            if api and urllib.parse.urlparse(api).scheme not in {"http", "https"}:
                return jsonify({"error": "la API debe ser http(s)://..."}), 400
            vps["api"] = api
        if body.get("token"):
            vps["token"] = str(body["token"]).strip()
        if "endpoint" in body:
            vps["endpoint"] = str(body["endpoint"]).strip()
        if "sync_interval" in body:
            try:
                interval = int(body["sync_interval"])
            except (TypeError, ValueError):
                return jsonify({"error": "intervalo inválido"}), 400
            if not (10 <= interval <= 3600):
                return jsonify({"error": "el intervalo debe estar entre 10 y 3600 segundos"}), 400
            config.setdefault("settings", {})["sync_interval"] = interval
        state.save(config)
    return jsonify({"ok": True})


@app.errorhandler(VPSError)
def handle_vps_error(exc: VPSError):
    return jsonify({"error": str(exc)}), 502


def background_sync() -> None:
    while True:
        config = state.load()
        interval = int((config.get("settings") or {}).get("sync_interval", 30))
        time.sleep(max(10, interval))
        config = state.load()
        if state.paired(config):
            try:
                sync_now()
            except Exception:  # noqa: BLE001 - el hilo no debe morir
                pass


def startup() -> None:
    config = state.load()
    if wireguard.config_text():
        ok, message = wireguard.apply_saved()
        if not ok:
            app.logger.warning("WireGuard no arrancó: %s", message)
    if state.paired(config) and wireguard.config_text():
        try:
            sync_now()
        except Exception as exc:  # noqa: BLE001
            app.logger.warning("sincronización inicial falló: %s", exc)
    else:
        proxy.stop()


if __name__ == "__main__":
    startup()
    threading.Thread(target=background_sync, daemon=True).start()
    app.run(host="0.0.0.0", port=8081, threaded=True)

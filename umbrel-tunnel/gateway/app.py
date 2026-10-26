"""umbrel-tunnel - gateway de Umbrel.

Expone servicios de Umbrel a través de un VPS con WireGuard. La app detecta
apps y servicios desde ``app-data`` (sin socket de Docker), deja elegir qué
puertos abrir y sincroniza los forwards con la API del VPS.

The API is protected by APP_PASSWORD because the shared Umbrel Docker network
must be treated as untrusted. Umbrel's proxy auth is disabled in the compose
file so this app owns the only login boundary.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import uuid
from datetime import timedelta

from flask import (
    Flask,
    g,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import detect
import i18n
import proxy
import state
import sync
import wireguard
from vps import VPSClient, VPSError

VERSION = os.environ.get("APP_VERSION", "1.0.0")
RESERVED_PUBLIC_PORTS = {22}
APP_PASSWORD = os.environ.get("APP_PASSWORD", "").strip()
DEV_MODE = os.environ.get("UMBREL_TUNNEL_DEV") == "1"
NETWORK_IP = os.environ.get("NETWORK_IP", "").strip()
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")

if not APP_PASSWORD:
    if DEV_MODE:
        APP_PASSWORD = "dev"
    else:
        raise RuntimeError("APP_PASSWORD no está definido; Umbrel debe inyectarlo")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = state.session_secret()
app.config.update(
    SESSION_COOKIE_NAME="ut_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=1 << 20,
)

STARTED = time.time()
_detect_lock = threading.Lock()
_detect_cache: dict = {"at": 0.0, "services": []}
_sync_lock = threading.Lock()
_last_sync: dict = {
    "ok": False,
    "created": 0,
    "updated": 0,
    "deleted": 0,
    "errors": [],
    "vps_status": None,
    "at": 0,
}

_login_attempts: dict[str, list[float]] = {}
_login_lock = threading.Lock()
LOGIN_WINDOW = 300
LOGIN_LIMIT = 5


class PairError(ValueError):
    def __init__(self, code: str, **params: object):
        super().__init__(code)
        self.code = code
        self.params = params


def _lang() -> str:
    return getattr(g, "lang", i18n.DEFAULT) if has_request_context() else i18n.DEFAULT


def _t(key: str, **params: object) -> str:
    return i18n.translate(_lang(), key, **params)


def api_error(code: str, status: int = 400, **params: object):
    payload = {"code": code, "error": _t(f"error.{code}", **params)}
    if params.get("detail"):
        payload["detail"] = str(params["detail"])
    return jsonify(payload), status


def _safe_next(value: str | None) -> str:
    value = (value or "/").strip()
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or any(ord(char) < 32 for char in value)
    ):
        return "/"
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme or parsed.netloc:
        return "/"
    return value


def _rate_limited(ip: str) -> bool:
    now = time.time()
    with _login_lock:
        attempts = [item for item in _login_attempts.get(ip, []) if item > now - LOGIN_WINDOW]
        _login_attempts[ip] = attempts
        return len(attempts) >= LOGIN_LIMIT


def _record_failure(ip: str) -> None:
    with _login_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


def _clear_failures(ip: str) -> None:
    with _login_lock:
        _login_attempts.pop(ip, None)


def _csrf_ok() -> bool:
    token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = str(session.get("csrf", ""))
    if not token or not expected:
        return False
    return hmac.compare_digest(str(token).encode("utf-8"), expected.encode("utf-8"))


@app.before_request
def authenticate():
    g.lang = i18n.resolve(request)
    g.t = lambda key, **params: i18n.translate(g.lang, key, **params)
    if request.endpoint in {"static", "login", "login_post", "health", "set_language"}:
        return None
    if request.path.startswith("/static/"):
        return None
    if not session.get("auth"):
        if request.path.startswith("/api/"):
            return api_error("unauthorized", 401)
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_ok():
        return api_error("csrf", 403)
    return None


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    )
    is_static = request.path.startswith("/static/")
    response.headers["Cache-Control"] = (
        "public, max-age=3600" if is_static else "no-store"
    )
    lang = getattr(g, "lang", None)
    already_set = "ut_lang=" in response.headers.get("Set-Cookie", "")
    if lang and not is_static and "ut_lang" not in request.cookies and not already_set:
        response.set_cookie("ut_lang", lang, max_age=31536000, samesite="Lax", httponly=True)
    return response


@app.context_processor
def inject_i18n():
    lang = _lang()
    session.setdefault("csrf", secrets.token_urlsafe(32))
    csrf_token = session.get("csrf", "")
    # Serialized once for the CSP-safe <script type="application/json"> block.
    # Escaping "<" prevents a catalog value from closing the script tag.
    config_json = json.dumps(
        {"lang": lang, "csrf": csrf_token, "i18n": i18n.catalog(lang)},
        ensure_ascii=False,
    ).replace("<", "\\u003c")
    return {
        "t": _t,
        "lang": lang,
        "config_json": config_json,
        "csrf_token": csrf_token,
        "app_version": VERSION,
    }


def present_sync(result: dict) -> dict:
    raw = [str(item) for item in (result.get("errors") or [])]
    presented = dict(result)
    presented["details"] = raw
    if raw:
        presented["errors"] = [_t("sync.failed_count", count=len(raw))]
    return presented


def detect_cached(force: bool = False) -> list[dict]:
    now = time.time()
    with _detect_lock:
        if force or now - _detect_cache["at"] > 15:
            config = state.load()
            _detect_cache["services"] = detect.detect_services(config.get("manual_services") or [])
            _detect_cache["at"] = now
        return list(_detect_cache["services"])


def sync_now() -> dict:
    global _last_sync
    with _sync_lock:
        with state.LOCK:
            config = state.load()
            vps = config.get("vps") or {}
            if state.paired(config) and not vps.get("peer_registered"):
                public = wireguard.public_key()
                if public:
                    try:
                        ensure_peer(config, public)
                        state.save(config)
                    except VPSError:
                        # The sync below will report the API error. The
                        # background loop retries registration.
                        pass
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


def validate_api_url(api: str, subnet: str) -> str:
    """Only accept the VPS API inside the tunnel subnet.

    A pairing code is user input. Without this check, a crafted code could
    point the gateway at an arbitrary internal host and make it send requests
    with the supplied Bearer token.
    """
    api = (api or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(api)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("api inválida")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("la API debe usar una IP del túnel") from exc
    try:
        network = wireguard.validate_subnet(subnet)
    except wireguard.WireGuardError as exc:
        raise ValueError(str(exc)) from exc
    if address not in network:
        raise ValueError("la API no pertenece a la subred del túnel")
    if parsed.port is None or not (1 <= parsed.port <= 65535):
        raise ValueError("puerto de la API inválido")
    return api


def decode_pair(code: str) -> dict:
    code = (code or "").strip()
    if not code.startswith("ut1."):
        raise PairError("pair_prefix")
    raw = code[4:]
    padded = raw + "=" * ((4 - len(raw) % 4) % 4)
    try:
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(data)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PairError("pair_invalid") from exc
    if not isinstance(payload, dict):
        raise PairError("pair_invalid")
    if payload.get("v") != 1:
        raise PairError("pair_version")
    api = str(payload.get("api") or "")
    parsed = urllib.parse.urlparse(api)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PairError("pair_api")
    if not str(payload.get("token") or "").strip():
        raise PairError("pair_token")

    subnet = str(payload.get("subnet") or "10.0.0.0/24").strip()
    try:
        wireguard.validate_subnet(subnet)
    except wireguard.WireGuardError as exc:
        raise PairError("pair_subnet", detail=str(exc)) from exc
    if wireguard.overlaps_network(subnet, NETWORK_IP):
        raise PairError("pair_overlap", subnet=subnet, network=NETWORK_IP)
    try:
        api = validate_api_url(api, subnet)
    except ValueError as exc:
        raise PairError("pair_api", detail=str(exc)) from exc

    umbrel_ip = str(payload.get("umbrel_ip") or "10.0.0.2").strip()
    try:
        wireguard.validate_address(umbrel_ip, subnet)
    except wireguard.WireGuardError as exc:
        raise PairError("pair_address", detail=str(exc)) from exc

    try:
        mtu = int(payload.get("mtu") or 1420)
    except (TypeError, ValueError) as exc:
        raise PairError("pair_mtu") from exc
    if not (1280 <= mtu <= 1500):
        raise PairError("pair_mtu")

    endpoint = str(payload.get("endpoint") or "").strip()
    if endpoint:
        try:
            wireguard.validate_endpoint(endpoint)
        except wireguard.WireGuardError as exc:
            raise PairError("pair_endpoint", detail=str(exc)) from exc
    server_pubkey = str(payload.get("server_pubkey") or "").strip()
    if server_pubkey and not wireguard.valid_key(server_pubkey):
        raise PairError("pair_pubkey")

    return {
        "api": api,
        "token": str(payload["token"]).strip(),
        "endpoint": endpoint,
        "server_pubkey": server_pubkey,
        "umbrel_ip": umbrel_ip,
        "subnet": subnet,
        "mtu": mtu,
    }


def validate_public_port(port: int) -> None:
    if not (1 <= port <= 65535):
        raise ValueError("invalid_public_port")
    if port in RESERVED_PUBLIC_PORTS:
        raise ValueError("reserved_public_port")


def allocate_tunnel_port(config: dict) -> int:
    used = {int(e.get("tunnel_port", 0)) for e in config.get("exposures", [])}
    settings = config.get("settings") or {}
    start = int(settings.get("tunnel_port_start", 20000))
    end = int(settings.get("tunnel_port_end", 29999))
    for port in range(start, end + 1):
        if port not in used:
            return port
    raise ValueError("no_tunnel_port")


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
    view = {
        **exposure,
        "vps_name": sync.vps_name(exposure),
        "sync_ok": not exposure.get("sync_error"),
    }
    if exposure.get("sync_error"):
        view["sync_error_detail"] = exposure["sync_error"]
        view["sync_error"] = _t("sync.forward_failed")
    return view


def ensure_peer(config: dict, public: str) -> None:
    vps = config.get("vps") or {}
    if not (vps.get("api") and vps.get("token")):
        raise VPSError("no emparejado")
    client = VPSClient(vps["api"], vps["token"])
    peers = client.list_peers()
    existing = next(
        (peer for peer in peers if str(peer.get("allowed_ip") or "") == vps.get("umbrel_ip")),
        None,
    )
    if existing is None:
        try:
            client.create_peer(
                {"name": "umbrel", "public_key": public, "allowed_ip": vps["umbrel_ip"]}
            )
        except VPSError as exc:
            if exc.status != 409:
                raise
            peers = client.list_peers()
            existing = next(
                (peer for peer in peers if str(peer.get("allowed_ip") or "") == vps.get("umbrel_ip")),
                None,
            )
            if existing is None:
                raise
            client.update_peer(existing["id"], {"public_key": public})
    elif existing.get("public_key") != public:
        client.update_peer(existing["id"], {"public_key": public})
    config["vps"]["peer_registered"] = True


@app.get("/login")
def login():
    if session.get("auth"):
        return redirect("/")
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return render_template("login.html", next_url=_safe_next(request.args.get("next")), error="")


@app.post("/login")
def login_post():
    ip = request.remote_addr or "unknown"
    next_url = _safe_next(request.form.get("next"))
    if not _csrf_ok():
        return render_template("login.html", next_url=next_url, error=_t("login.csrf")), 403
    if _rate_limited(ip):
        return render_template("login.html", next_url=next_url, error=_t("login.rate_limited")), 429
    password = request.form.get("password", "")
    if not APP_PASSWORD or not hmac.compare_digest(
        password.encode("utf-8"), APP_PASSWORD.encode("utf-8")
    ):
        _record_failure(ip)
        return render_template("login.html", next_url=next_url, error=_t("login.invalid")), 401
    _clear_failures(ip)
    session.clear()
    session["auth"] = True
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True
    return redirect(next_url)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/lang/<code>")
def set_language(code: str):
    code = code if code in i18n.SUPPORTED else i18n.DEFAULT
    response = redirect(_safe_next(request.args.get("next")))
    response.set_cookie("ut_lang", code, max_age=31536000, samesite="Lax", httponly=True)
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "version": VERSION})


@app.get("/api/status")
def status():
    config = state.load()
    vps = config.get("vps") or {}
    wg = wireguard.status()
    return jsonify(
        {
            "version": VERSION,
            "uptime": int(time.time() - STARTED),
            "paired": state.paired(config),
            "vps": {
                "api": vps.get("api", ""),
                "endpoint": vps.get("endpoint", ""),
                "server_pubkey": vps.get("server_pubkey", ""),
                "umbrel_ip": vps.get("umbrel_ip", ""),
                "subnet": vps.get("subnet", ""),
                "peer_registered": bool(vps.get("peer_registered")),
            },
            "wg": wg,
            "exposures": len(config.get("exposures", [])),
            "exposures_enabled": sum(1 for e in config.get("exposures", []) if e.get("enabled", True)),
            "services": len(detect_cached()),
            "manual_services": len(config.get("manual_services", [])),
            "last_sync": present_sync(_last_sync),
        }
    )


@app.get("/api/services")
def services():
    config = state.load()
    by_service = {
        (e.get("service_id"), e.get("target_port"), e.get("protocol", "tcp")): e
        for e in config.get("exposures", [])
    }
    result = []
    for svc in detect_cached():
        item = dict(svc)
        exposure = by_service.get((svc["id"], svc["target_port"], svc.get("protocol", "tcp")))
        item["exposed"] = exposure is not None
        item["exposure_enabled"] = bool(exposure.get("enabled", True)) if exposure else False
        item["default_public_port"] = 2222 if svc["target_port"] == 22 else svc["target_port"]
        item["can_open"] = svc.get("protocol", "tcp") == "tcp"
        result.append(item)
    return jsonify(result)


@app.post("/api/services/refresh")
def refresh_services():
    detect_cached(force=True)
    return jsonify(detect_cached())


@app.get("/api/exposures")
def list_exposures():
    config = state.load()
    return jsonify([exposure_view(e) for e in config.get("exposures", [])])


@app.post("/api/exposures")
def create_exposure():
    body = request.get_json(silent=True) or {}
    service = service_by_id(str(body.get("service_id") or ""))
    if not service:
        return api_error("service_not_found", 404)
    if service.get("protocol", "tcp") != "tcp":
        return api_error("unsupported_protocol", 400)

    try:
        public_port = int(body.get("public_port") or service["target_port"])
    except (TypeError, ValueError):
        return api_error("invalid_public_port", 400)
    try:
        validate_public_port(public_port)
    except ValueError as exc:
        return api_error(str(exc), 400)

    with state.LOCK:
        config = state.load()
        if public_port_in_use(config, public_port):
            return api_error("public_port_in_use", 409, port=public_port)
        try:
            tunnel_port = allocate_tunnel_port(config)
        except ValueError as exc:
            return api_error(str(exc), 409)
        exposure = {
            "id": uuid.uuid4().hex[:12],
            "service_id": service["id"],
            "name": str(body.get("name") or f"{service['app']} - {service['name']}")[:80],
            "app": service["app"],
            "service": service["name"],
            "target_ip": service["target_ip"],
            "target_port": service["target_port"],
            "tunnel_ip": (config.get("vps") or {}).get("umbrel_ip") or "10.0.0.2",
            "public_port": public_port,
            "tunnel_port": tunnel_port,
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
    return jsonify({"exposure": exposure_view(saved or exposure), "sync": present_sync(result)}), 201


@app.patch("/api/exposures/<exposure_id>")
def update_exposure(exposure_id: str):
    body = request.get_json(silent=True) or {}
    with state.LOCK:
        config = state.load()
        exposure = state.find_exposure(config, exposure_id)
        if not exposure:
            return api_error("exposure_not_found", 404)

        if "public_port" in body:
            try:
                public_port = int(body["public_port"])
                validate_public_port(public_port)
            except (TypeError, ValueError) as exc:
                code = str(exc) if isinstance(exc, ValueError) and str(exc) in {"invalid_public_port", "reserved_public_port"} else "invalid_public_port"
                return api_error(code, 400)
            if public_port_in_use(config, public_port, ignore_id=exposure_id):
                return api_error("public_port_in_use", 409, port=public_port)
            exposure["public_port"] = public_port
        if "enabled" in body:
            if body["enabled"] and str(exposure.get("protocol") or "tcp") != "tcp":
                return api_error("unsupported_protocol", 400)
            exposure["enabled"] = bool(body["enabled"])
        if "name" in body and str(body["name"]).strip():
            exposure["name"] = str(body["name"]).strip()[:80]
        exposure["vps_name"] = sync.vps_name(exposure)
        state.save(config)

    result = sync_now()
    current = state.load()
    saved = state.find_exposure(current, exposure_id)
    return jsonify({"exposure": exposure_view(saved or {}), "sync": present_sync(result)})


@app.delete("/api/exposures/<exposure_id>")
def delete_exposure(exposure_id: str):
    with state.LOCK:
        config = state.load()
        exposure = state.find_exposure(config, exposure_id)
        if not exposure:
            return api_error("exposure_not_found", 404)
        forward_id = exposure.get("vps_forward_id")
        if forward_id and state.paired(config):
            vps = config.get("vps") or {}
            try:
                VPSClient(vps["api"], vps["token"]).delete_forward(forward_id)
            except VPSError as exc:
                # A forward already removed on the VPS must not block cleanup.
                if exc.status != 404:
                    return api_error("vps_close_failed", 502, detail=str(exc))
        config["exposures"] = [e for e in config["exposures"] if e.get("id") != exposure_id]
        state.save(config)

    result = sync_now()
    return jsonify({"ok": True, "sync": present_sync(result)})


@app.post("/api/sync")
def sync_route():
    return jsonify(present_sync(sync_now()))


@app.post("/api/pair")
def pair():
    body = request.get_json(silent=True) or {}
    try:
        payload = decode_pair(str(body.get("code") or ""))
    except PairError as exc:
        return api_error(exc.code, 400, **exc.params)

    api = payload["api"].rstrip("/")
    with state.LOCK:
        config = state.load()
        config["vps"] = {
            "api": api,
            "token": payload["token"],
            "endpoint": payload["endpoint"],
            "server_pubkey": payload["server_pubkey"],
            "umbrel_ip": payload["umbrel_ip"],
            "subnet": payload["subnet"],
            "mtu": payload["mtu"],
            "peer_registered": False,
        }
        state.save(config)

    if not payload["endpoint"] or not payload["server_pubkey"]:
        return jsonify(
            {
                "ok": False,
                "paired": True,
                "manual": True,
                "wg": _t("pair.manual_required"),
                "sync": {
                    "ok": False,
                    "errors": [_t("pair.wg_pending")],
                    "details": [],
                    "at": time.time(),
                },
            }
        )

    try:
        private, public = wireguard.ensure_keypair()
        text = wireguard.build_config(
            private,
            payload["umbrel_ip"],
            payload["server_pubkey"],
            payload["endpoint"],
            payload["subnet"],
            payload["mtu"],
        )
        wireguard.save_config(text)
        wg_ok, wg_message = wireguard.apply_saved()
    except wireguard.WireGuardError as exc:
        return api_error("wg_config", 400, detail=str(exc))

    with state.LOCK:
        config = state.load()
        try:
            ensure_peer(config, public)
            state.save(config)
        except VPSError as exc:
            state.save(config)
            return (
                jsonify(
                    {
                        "ok": False,
                        "paired": True,
                        "manual": False,
                        "public_key": public,
                        "wg": wg_message,
                        "code": "peer_register_failed",
                        "error": _t("error.peer_register_failed"),
                        "detail": str(exc),
                    }
                ),
                502,
            )

    result = sync_now() if wg_ok else {
        "ok": False,
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "errors": [wg_message],
        "vps_status": None,
        "at": time.time(),
    }
    return jsonify(
        {
            "ok": bool(wg_ok),
            "paired": True,
            "manual": False,
            "public_key": public,
            "wg": wg_message,
            "sync": present_sync(result),
        }
    )


@app.post("/api/register")
def register_peer():
    with state.LOCK:
        config = state.load()
        if not state.paired(config):
            return api_error("not_paired", 409)
        public = wireguard.public_key()
        if not public:
            return api_error("wg_not_configured", 409)
        try:
            ensure_peer(config, public)
        except VPSError as exc:
            return api_error("peer_register_failed", 502, detail=str(exc))
        state.save(config)
    return jsonify({"ok": True, "public_key": public})


@app.post("/api/unpair")
def unpair():
    with state.LOCK:
        config = state.load()
        vps = config.get("vps") or {}
        if vps.get("api") and vps.get("token"):
            client = VPSClient(vps["api"], vps["token"])
            try:
                for peer in client.list_peers():
                    if str(peer.get("allowed_ip") or "") == vps.get("umbrel_ip"):
                        client.delete_peer(peer["id"])
            except VPSError:
                pass
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
    config = state.load()
    vps = config.get("vps") or {}
    return jsonify(
        {
            "config": wireguard.redacted_config(),
            "status": wireguard.status(),
            "address": wireguard.address(),
            "subnet": wireguard.subnet() or vps.get("subnet", ""),
            "public_key": wireguard.public_key(),
            "endpoint": vps.get("endpoint", ""),
            "server_pubkey": vps.get("server_pubkey", ""),
        }
    )


@app.post("/api/wireguard/manual")
def manual_wireguard():
    body = request.get_json(silent=True) or {}
    config = state.load()
    vps = config.get("vps") or {}
    endpoint = str(body.get("endpoint") or vps.get("endpoint") or "").strip()
    server_pubkey = str(body.get("server_pubkey") or vps.get("server_pubkey") or "").strip()
    client_ip = str(body.get("client_ip") or vps.get("umbrel_ip") or "10.0.0.2").strip()
    subnet_cidr = str(body.get("subnet") or vps.get("subnet") or "10.0.0.0/24").strip()
    try:
        mtu = int(body.get("mtu") or vps.get("mtu") or 1420)
    except (TypeError, ValueError):
        return api_error("pair_mtu", 400)
    if not endpoint or not server_pubkey:
        return api_error("pair_manual_missing", 400)
    try:
        if wireguard.overlaps_network(subnet_cidr, NETWORK_IP):
            return api_error("pair_overlap", 400, subnet=subnet_cidr, network=NETWORK_IP)
        private, public = wireguard.ensure_keypair()
        text = wireguard.build_config(private, client_ip, server_pubkey, endpoint, subnet_cidr, mtu)
        wireguard.save_config(text)
        ok, message = wireguard.apply_saved()
    except wireguard.WireGuardError as exc:
        return api_error("wg_config", 400, detail=str(exc))

    with state.LOCK:
        config = state.load()
        config["vps"] = {
            **(config.get("vps") or {}),
            "endpoint": endpoint,
            "server_pubkey": server_pubkey,
            "umbrel_ip": client_ip,
            "subnet": subnet_cidr,
            "mtu": mtu,
            "peer_registered": False,
        }
        state.save(config)
        if state.paired(config):
            try:
                ensure_peer(config, public)
                state.save(config)
            except VPSError:
                pass

    return jsonify(
        {
            "public_key": public,
            "applied": ok,
            "message": message,
            "instructions": _t(
                "pair.manual_instructions", public_key=public, client_ip=client_ip
            ),
        }
    )


@app.post("/api/wireguard/rotate")
def rotate_wireguard():
    config = state.load()
    vps = config.get("vps") or {}
    endpoint = str(vps.get("endpoint") or "")
    server_pubkey = str(vps.get("server_pubkey") or "")
    client_ip = str(vps.get("umbrel_ip") or "10.0.0.2")
    subnet_cidr = str(vps.get("subnet") or "10.0.0.0/24")
    mtu = int(vps.get("mtu") or 1420)
    if not endpoint or not server_pubkey:
        return api_error("wg_not_configured", 409)

    old_text = wireguard.config_text()
    old_private = wireguard.private_key()
    try:
        private, public = wireguard.generate_keypair()
        text = wireguard.build_config(private, client_ip, server_pubkey, endpoint, subnet_cidr, mtu)
        wireguard.save_private_key(private)
        wireguard.save_config(text)
        ok, message = wireguard.apply_saved()
        if not ok:
            raise wireguard.WireGuardError(message)
        with state.LOCK:
            current = state.load()
            current["vps"] = {**(current.get("vps") or {}), "peer_registered": False}
            state.save(current)
            ensure_peer(current, public)
            state.save(current)
    except (wireguard.WireGuardError, VPSError) as exc:
        # Roll back to the last working key/config.
        try:
            if old_private:
                wireguard.save_private_key(old_private)
            if old_text:
                wireguard.save_config(old_text)
                wireguard.apply_saved()
        except wireguard.WireGuardError:
            pass
        return api_error("wg_rotate_failed", 502, detail=str(exc))

    result = sync_now()
    return jsonify(
        {"ok": True, "public_key": public, "message": message, "sync": present_sync(result)}
    )


@app.get("/api/settings")
def get_settings():
    config = state.load()
    vps = config.get("vps") or {}
    return jsonify(
        {
            "api": vps.get("api", ""),
            "token_set": bool(vps.get("token")),
            "endpoint": vps.get("endpoint", ""),
            "subnet": vps.get("subnet", ""),
            "umbrel_ip": vps.get("umbrel_ip", ""),
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
            parsed = urllib.parse.urlparse(api)
            if api and (parsed.scheme not in {"http", "https"} or not parsed.netloc):
                return api_error("invalid_api", 400)
            subnet = str(vps.get("subnet") or "").strip()
            if api and subnet:
                try:
                    api = validate_api_url(api, subnet)
                except ValueError:
                    return api_error("invalid_api", 400)
            vps["api"] = api
        if body.get("token"):
            vps["token"] = str(body["token"]).strip()
        if "endpoint" in body:
            endpoint = str(body["endpoint"]).strip()
            if endpoint:
                try:
                    wireguard.validate_endpoint(endpoint)
                except wireguard.WireGuardError:
                    return api_error("pair_endpoint", 400)
            vps["endpoint"] = endpoint
        if "sync_interval" in body:
            try:
                interval = int(body["sync_interval"])
            except (TypeError, ValueError):
                return api_error("invalid_interval", 400)
            if not (10 <= interval <= 3600):
                return api_error("invalid_interval_range", 400)
            config.setdefault("settings", {})["sync_interval"] = interval
        state.save(config)
    return jsonify({"ok": True})


@app.get("/api/manual-services")
def list_manual_services():
    return jsonify(state.load().get("manual_services") or [])


@app.post("/api/manual-services")
def add_manual_service():
    body = request.get_json(silent=True) or {}
    host = str(body.get("host") or "").strip()
    name = str(body.get("name") or "").strip()[:80]
    protocol = str(body.get("protocol") or "tcp").lower()
    try:
        port = int(body.get("port"))
    except (TypeError, ValueError):
        return api_error("invalid_manual_service", 400)
    if not HOST_RE.match(host) or not (1 <= port <= 65535) or protocol not in {"tcp", "udp"}:
        return api_error("invalid_manual_service", 400)
    entry = {
        "id": uuid.uuid4().hex[:8],
        "name": name or f"{host}:{port}",
        "host": host,
        "port": port,
        "protocol": protocol,
    }
    with state.LOCK:
        config = state.load()
        config.setdefault("manual_services", []).append(entry)
        state.save(config)
    detect_cached(force=True)
    return jsonify(entry), 201


@app.delete("/api/manual-services/<service_id>")
def delete_manual_service(service_id: str):
    with state.LOCK:
        config = state.load()
        if any(
            str(exposure.get("service_id", "")).startswith(f"manual:{service_id}:")
            for exposure in config.get("exposures", [])
        ):
            return api_error("manual_service_in_use", 409)
        before = len(config.get("manual_services") or [])
        config["manual_services"] = [
            item for item in (config.get("manual_services") or []) if item.get("id") != service_id
        ]
        if len(config["manual_services"]) == before:
            return api_error("manual_service_not_found", 404)
        state.save(config)
    detect_cached(force=True)
    return jsonify({"ok": True})


@app.errorhandler(VPSError)
def handle_vps_error(exc: VPSError):
    return api_error("vps", 502, detail=str(exc))


@app.errorhandler(404)
def handle_not_found(_exc):
    if request.path.startswith("/api/"):
        return api_error("not_found", 404)
    return redirect(url_for("index"))


@app.errorhandler(413)
def handle_too_large(_exc):
    return api_error("too_large", 413)


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
    if state.paired(config) and not (config.get("vps") or {}).get("peer_registered"):
        public = wireguard.public_key()
        if public:
            try:
                ensure_peer(config, public)
                state.save(config)
            except VPSError as exc:
                app.logger.warning("registro del peer falló: %s", exc)
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

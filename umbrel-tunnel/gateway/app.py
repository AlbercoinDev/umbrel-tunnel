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
import shlex
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

VERSION = os.environ.get("APP_VERSION", "1.0.2")
RESERVED_PUBLIC_PORTS = {22}
APP_PASSWORD = os.environ.get("APP_PASSWORD", "").strip()
DEV_MODE = os.environ.get("UMBREL_TUNNEL_DEV") == "1"
NETWORK_IP = os.environ.get("NETWORK_IP", "").strip()
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
PAIR_TOKEN_RE = re.compile(r"(ut1\.[A-Za-z0-9_=-]+)")

# Where the app points users to install the VPS side. Both values can be
# overridden for forks, testing or air-gapped mirrors.
DEFAULT_INSTALL_URL = (
    "https://raw.githubusercontent.com/AlbercoinDev/umbrel-tunnel/main/vps/install.sh"
)
DEFAULT_BINARY_BASE = (
    "https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download"
)
INSTALL_URL = (
    os.environ.get("UMBREL_TUNNEL_INSTALL_URL", "").strip() or DEFAULT_INSTALL_URL
)
BINARY_BASE = (
    os.environ.get("UMBREL_TUNNEL_BINARY_BASE", "").strip() or DEFAULT_BINARY_BASE
)

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
_sync_lock = threading.RLock()
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


class BootstrapError(ValueError):
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
        "no-cache" if is_static else "no-store"
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
    presented["error_count"] = len(raw)
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


_SYNC_FIELDS = (
    "vps_forward_id",
    "vps_name",
    "tunnel_ip",
    "sync_error",
    "sync_error_status",
    "proxy_error",
    "last_sync",
)


def _persist_sync_state(snapshot: dict) -> None:
    """Merge the fields owned by sync into the latest on-disk config.

    ``sync.sync`` runs network calls, so the state lock must stay free while it
    works. Another request can add a manual service or change settings during
    that window; reloading and merging only the sync-owned fields keeps those
    changes instead of overwriting them with the stale snapshot.
    """
    with state.LOCK:
        current = state.load()
        current_by_id = {
            str(exposure.get("id")): exposure
            for exposure in current.get("exposures", [])
        }
        for saved in snapshot.get("exposures", []):
            target = current_by_id.get(str(saved.get("id")))
            if target is None:
                continue
            for field in _SYNC_FIELDS:
                if field in saved:
                    target[field] = saved[field]
                elif field == "proxy_error":
                    target.pop(field, None)
        snapshot_vps = snapshot.get("vps") or {}
        if snapshot_vps.get("peer_registered"):
            current.setdefault("vps", {})["peer_registered"] = True
        state.save(current)


def sync_now() -> dict:
    global _last_sync
    with _sync_lock:
        config = state.load()
        vps = config.get("vps") or {}
        if state.paired(config) and not vps.get("peer_registered"):
            public = wireguard.public_key()
            if public:
                try:
                    ensure_peer(config, public)
                except VPSError as exc:
                    # The sync below reports the API error. The background loop
                    # retries registration.
                    app.logger.warning("registro del peer falló: %s", exc)
        try:
            result = sync.sync(config)
        except Exception as exc:  # noqa: BLE001 - se devuelve al usuario
            app.logger.exception("sincronización inesperada")
            result = {
                "ok": False,
                "created": 0,
                "updated": 0,
                "deleted": 0,
                "errors": [f"error inesperado: {exc}"],
                "vps_status": None,
                "at": time.time(),
            }
        _persist_sync_state(config)
        _last_sync = result
        if result.get("errors"):
            app.logger.warning("sync con errores: %s", result["errors"])
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


def _bootstrap_api(bootstrap: dict) -> str:
    return f"http://{bootstrap.get('server_ip', '')}:{int(bootstrap.get('api_port') or 0)}"


def _bootstrap_endpoint(bootstrap: dict) -> str:
    return f"{bootstrap.get('vps_ip', '')}:{int(bootstrap.get('wg_port') or 0)}"


def install_command(bootstrap: dict) -> str:
    """Build the one-line VPS installer command shown to the user.

    Every value is shell-quoted because it is pasted into a root shell.
    """
    args = [
        "--endpoint",
        str(bootstrap["vps_ip"]),
        "--token",
        str(bootstrap["token"]),
        "--umbrel-pubkey",
        str(bootstrap["public_key"]),
        "--subnet",
        str(bootstrap["subnet"]),
        "--server-ip",
        str(bootstrap["server_ip"]),
        "--umbrel-ip",
        str(bootstrap["umbrel_ip"]),
        "--api-port",
        str(int(bootstrap["api_port"])),
        "--wg-port",
        str(int(bootstrap["wg_port"])),
        "--mtu",
        str(int(bootstrap["mtu"])),
        "--binary-base",
        BINARY_BASE,
    ]
    return "curl -fsSL {} | sudo bash -s -- {}".format(
        shlex.quote(INSTALL_URL), " ".join(shlex.quote(item) for item in args)
    )


def bootstrap_view(bootstrap: dict) -> dict:
    """Public (browser-facing) view of a pending bootstrap.

    The token is deliberately omitted: it is already embedded in the command
    and should not be duplicated in every status response.
    """
    return {
        "active": True,
        "vps_ip": bootstrap.get("vps_ip", ""),
        "endpoint": _bootstrap_endpoint(bootstrap),
        "api": _bootstrap_api(bootstrap),
        "subnet": bootstrap.get("subnet", ""),
        "server_ip": bootstrap.get("server_ip", ""),
        "umbrel_ip": bootstrap.get("umbrel_ip", ""),
        "api_port": int(bootstrap.get("api_port") or 0),
        "wg_port": int(bootstrap.get("wg_port") or 0),
        "mtu": int(bootstrap.get("mtu") or 0),
        "public_key": bootstrap.get("public_key", ""),
        "token_set": bool(bootstrap.get("token")),
        "command": install_command(bootstrap),
        "install_url": INSTALL_URL,
        "binary_base": BINARY_BASE,
        "created_at": bootstrap.get("created_at", 0),
    }


def _int_in_range(value: object, minimum: int, maximum: int, code: str) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise BootstrapError(code) from exc
    if not (minimum <= number <= maximum):
        raise BootstrapError(code)
    return number


def validate_vps_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError as exc:
        raise BootstrapError("invalid_vps_ip") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise BootstrapError("invalid_vps_ip")
    # A public VPS is required. Dev mode keeps LAN addresses usable for tests.
    if not address.is_global and not DEV_MODE:
        raise BootstrapError("vps_ip_not_public")
    return str(address)


def build_bootstrap(body: dict, existing: dict | None = None) -> dict:
    """Create the pending bootstrap used by the app-first onboarding."""
    existing = existing or {}
    vps_ip = validate_vps_ip(str(body.get("vps_ip") or ""))
    api_port = _int_in_range(body.get("api_port", 8080), 1, 65535, "invalid_bootstrap")
    wg_port = _int_in_range(body.get("wg_port", 51820), 1, 65535, "invalid_bootstrap")
    mtu = _int_in_range(body.get("mtu", 1420), 1280, 1500, "pair_mtu")

    subnet = str(body.get("subnet") or "10.0.0.0/24").strip()
    try:
        network = wireguard.validate_subnet(subnet)
    except wireguard.WireGuardError as exc:
        raise BootstrapError("pair_subnet", detail=str(exc)) from exc
    if wireguard.overlaps_network(subnet, NETWORK_IP):
        raise BootstrapError("pair_overlap", subnet=subnet, network=NETWORK_IP)

    server_ip = str(body.get("server_ip") or (network.network_address + 1)).strip()
    umbrel_ip = str(body.get("umbrel_ip") or (network.network_address + 2)).strip()
    try:
        server_address = wireguard.validate_address(server_ip, subnet)
        umbrel_address = wireguard.validate_address(umbrel_ip, subnet)
    except wireguard.WireGuardError as exc:
        raise BootstrapError("pair_address", detail=str(exc)) from exc
    if server_address == umbrel_address:
        raise BootstrapError("invalid_bootstrap")

    try:
        _, public_key = wireguard.ensure_keypair()
    except wireguard.WireGuardError as exc:
        raise BootstrapError("wg_config", detail=str(exc)) from exc

    # Keep the token stable when the user regenerates the command for the same
    # VPS; changing the VPS invalidates the old command.
    token = str(existing.get("token") or "")
    if not token or existing.get("vps_ip") != vps_ip:
        token = secrets.token_urlsafe(32)

    return {
        "vps_ip": vps_ip,
        "api_port": api_port,
        "wg_port": wg_port,
        "subnet": str(network),
        "server_ip": str(server_address),
        "umbrel_ip": str(umbrel_address),
        "mtu": mtu,
        "token": token,
        "public_key": public_key,
        "created_at": time.time(),
    }


def bootstrap_mismatch(payload: dict, bootstrap: dict) -> str:
    """Return the first field of the ut1 code that differs from the bootstrap."""
    expected = {
        "token": str(bootstrap.get("token") or ""),
        "api": _bootstrap_api(bootstrap),
        "endpoint": _bootstrap_endpoint(bootstrap),
        "subnet": str(bootstrap.get("subnet") or ""),
        "umbrel_ip": str(bootstrap.get("umbrel_ip") or ""),
    }
    for field, want in expected.items():
        if want and str(payload.get(field) or "") != want:
            return field
    want_mtu = bootstrap.get("mtu")
    if want_mtu:
        try:
            got_mtu = int(payload.get("mtu") or 0)
        except (TypeError, ValueError):
            got_mtu = 0
        if got_mtu != int(want_mtu):
            return "mtu"
    return ""


def decode_pair(code: str) -> dict:
    code = (code or "").strip()
    # The installer prints a whole block; accept it and extract the code.
    if code and not code.startswith("ut1."):
        match = PAIR_TOKEN_RE.search(code)
        if match:
            code = match.group(1)
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
        subnet = str(wireguard.validate_subnet(subnet))
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


def allocate_public_port(config: dict, preferred: int | None = None) -> tuple[int, bool]:
    """Pick a public port, preferring ``preferred`` when it is free.

    Returns ``(port, changed)``. A busy preferred port is not an error: the
    most common failure when opening a service was the default public port
    already being used, so the caller opens the service on the next free port
    and tells the user which one was chosen.
    """
    if preferred is not None:
        validate_public_port(preferred)
        if not public_port_in_use(config, preferred):
            return preferred, False

    used = {int(e.get("public_port", 0)) for e in config.get("exposures", [])}
    # Internal HAProxy ports live on the Umbrel side, but keeping the public
    # range disjoint makes diagnostics much easier to read.
    used.update(int(e.get("tunnel_port", 0)) for e in config.get("exposures", []))
    settings = config.get("settings") or {}
    start = int(settings.get("public_port_start", 20000))
    end = int(settings.get("public_port_end", 29999))
    for port in range(start, end + 1):
        if port in RESERVED_PUBLIC_PORTS or port in used:
            continue
        return port, True
    for port in range(1024, 65536):
        if port in RESERVED_PUBLIC_PORTS or port in used:
            continue
        return port, True
    raise ValueError("no_public_port")


def _requested_public_port(body: dict) -> int | None:
    raw = body.get("public_port")
    if raw is None or str(raw).strip() == "":
        return None
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_public_port") from exc
    validate_public_port(port)
    return port


def _find_exposure_for_service(config: dict, service: dict) -> dict | None:
    for exposure in config.get("exposures", []):
        if exposure.get("service_id") == service["id"]:
            return exposure
    target = (
        str(service.get("target_ip") or ""),
        int(service.get("target_port") or 0),
        str(service.get("protocol") or "tcp"),
    )
    for exposure in config.get("exposures", []):
        current = (
            str(exposure.get("target_ip") or ""),
            int(exposure.get("target_port") or 0),
            str(exposure.get("protocol") or "tcp"),
        )
        if current == target:
            return exposure
    return None


def _create_or_open_exposure(
    config: dict,
    service: dict,
    name: str = "",
    requested_port: int | None = None,
) -> tuple[dict, bool, bool]:
    """Create an exposure or return the existing one for the same target.

    The caller must hold ``_sync_lock``. Returns ``(exposure, port_changed,
    existing)``.
    """
    existing = _find_exposure_for_service(config, service)
    if existing is not None:
        if not existing.get("enabled", True):
            existing["enabled"] = True
        if name and not existing.get("name"):
            existing["name"] = name[:80]
        return existing, False, True

    public_port, changed = allocate_public_port(config, requested_port)
    tunnel_port = allocate_tunnel_port(config)
    exposure = {
        "id": uuid.uuid4().hex[:12],
        "service_id": service["id"],
        "name": (name or f"{service['app']} - {service['name']}")[:80],
        "app": service["app"],
        "service": service["name"],
        "target_ip": service["target_ip"],
        "target_port": service["target_port"],
        "tunnel_ip": (config.get("vps") or {}).get("umbrel_ip") or "10.0.0.2",
        "public_port": public_port,
        "tunnel_port": tunnel_port,
        "protocol": "tcp",
        "enabled": True,
        "sensitive": bool(service.get("sensitive")),
        "vps_forward_id": None,
        "vps_name": "",
        "sync_error": "",
        "sync_error_status": None,
        "last_sync": 0,
    }
    config.setdefault("exposures", []).append(exposure)
    return exposure, changed, False


def _sync_exposure(exposure_id: str, retry_conflict: bool = True) -> tuple[dict | None, dict]:
    """Sync and, if the VPS rejects the public port, retry on a free one."""
    result = sync_now()
    if retry_conflict:
        current = state.load()
        exposure = state.find_exposure(current, exposure_id)
        if exposure and int(exposure.get("sync_error_status") or 0) == 409:
            new_port = None
            previous_port = exposure.get("public_port")
            # Only the state mutation happens under the lock; the retry sync
            # performs network calls and must leave the state lock free.
            with state.LOCK:
                current = state.load()
                exposure = state.find_exposure(current, exposure_id)
                if exposure is not None:
                    try:
                        new_port, _ = allocate_public_port(current)
                    except ValueError:
                        new_port = None
                    if new_port and new_port != int(exposure.get("public_port", 0)):
                        exposure["public_port"] = new_port
                        exposure["sync_error"] = ""
                        exposure["sync_error_status"] = None
                        state.save(current)
                    else:
                        new_port = None
            if new_port:
                app.logger.warning(
                    "puerto público %s rechazado por el VPS; reintentando con %s",
                    previous_port,
                    new_port,
                )
                result = sync_now()
                result["retried_public_port"] = new_port
    current = state.load()
    return state.find_exposure(current, exposure_id), result


def manual_service_view(item: dict, config: dict | None = None) -> dict:
    config = config or state.load()
    prefix = f"manual:{item.get('id')}:"
    exposure = next(
        (
            e
            for e in config.get("exposures", [])
            if str(e.get("service_id", "")).startswith(prefix)
        ),
        None,
    )
    return {
        **item,
        "target": f"{item.get('host')}:{item.get('port')}",
        "exposure": exposure_view(exposure) if exposure else None,
    }


def _manual_service(config: dict, service_id: str) -> dict | None:
    for item in config.get("manual_services") or []:
        if str(item.get("id")) == service_id:
            return item
    return None


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
    bootstrap = config.get("bootstrap") or {}
    paired = state.paired(config)
    wg = wireguard.status()
    return jsonify(
        {
            "version": VERSION,
            "uptime": int(time.time() - STARTED),
            "paired": paired,
            "bootstrap": bool(bootstrap) and not paired,
            "bootstrap_vps_ip": (bootstrap.get("vps_ip", "") if bootstrap and not paired else ""),
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
            "exposures_failed": sum(1 for e in config.get("exposures", []) if e.get("sync_error")),
            "services": len(detect_cached()),
            "manual_services": len(config.get("manual_services", [])),
            "last_sync": present_sync(_last_sync),
        }
    )


@app.get("/api/diagnostics")
def diagnostics():
    """Read-only checks used by the Advanced tab to explain a failed open."""
    config = state.load()
    vps = config.get("vps") or {}
    paired = state.paired(config)
    wg = wireguard.status()
    public_key = wireguard.public_key()
    checks = [
        {"id": "paired", "ok": paired},
        {"id": "wg", "ok": bool(wg.get("running"))},
    ]
    vps_report = {
        "api": vps.get("api", ""),
        "reachable": False,
        "health": None,
        "status": None,
        "error": "",
    }
    peer_report = {
        "registered": bool(vps.get("peer_registered")),
        "present": None,
        "matches": None,
        "public_key": public_key,
        "error": "",
    }
    forwards_report = {"total": 0, "ours": 0, "items": [], "error": ""}

    if paired:
        client = VPSClient(vps["api"], vps["token"], timeout=4.0)
        try:
            vps_report["health"] = client.health()
            vps_report["reachable"] = True
        except VPSError as exc:
            vps_report["error"] = str(exc)
        if vps_report["reachable"]:
            try:
                vps_report["status"] = client.status()
            except VPSError as exc:
                vps_report["error"] = str(exc)
            try:
                peers = client.list_peers()
                ours = next(
                    (
                        peer
                        for peer in peers
                        if str(peer.get("allowed_ip") or "") == vps.get("umbrel_ip")
                    ),
                    None,
                )
                peer_report["present"] = ours is not None
                peer_report["matches"] = bool(
                    ours and str(ours.get("public_key") or "") == str(public_key or "")
                )
            except VPSError as exc:
                peer_report["error"] = str(exc)
            try:
                forwards = client.list_forwards()
                mine = [
                    forward
                    for forward in forwards
                    if str(forward.get("name") or "").startswith(sync.NAME_PREFIX)
                ]
                forwards_report["total"] = len(forwards)
                forwards_report["ours"] = len(mine)
                forwards_report["items"] = [
                    {
                        "id": forward.get("id"),
                        "name": forward.get("name"),
                        "public_port": forward.get("public_port"),
                        "target_ip": forward.get("target_ip"),
                        "target_port": forward.get("target_port"),
                        "protocol": forward.get("protocol"),
                        "enabled": forward.get("enabled"),
                    }
                    for forward in mine
                ]
            except VPSError as exc:
                forwards_report["error"] = str(exc)

    checks.append(
        {
            "id": "vps",
            "ok": vps_report["reachable"],
            "detail": vps_report["error"],
        }
    )
    checks.append(
        {
            "id": "peer",
            "ok": bool(peer_report["present"] and peer_report["matches"]),
            "detail": peer_report["error"],
        }
    )
    checks.append(
        {
            "id": "forwards",
            "ok": not forwards_report["error"],
            "detail": forwards_report["error"],
        }
    )
    proxy_status = proxy.status()
    checks.append({"id": "proxy", "ok": bool(proxy_status.get("running"))})

    return jsonify(
        {
            "version": VERSION,
            "paired": paired,
            "wg": wg,
            "vps": vps_report,
            "peer": peer_report,
            "forwards": forwards_report,
            "proxy": proxy_status,
            "checks": checks,
            "exposures": [
                {
                    "id": exposure.get("id"),
                    "name": exposure.get("name"),
                    "public_port": exposure.get("public_port"),
                    "enabled": bool(exposure.get("enabled", True)),
                    "sync_ok": not exposure.get("sync_error"),
                    "sync_error": exposure.get("sync_error") or "",
                    "vps_forward_id": exposure.get("vps_forward_id"),
                }
                for exposure in config.get("exposures", [])
            ],
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
    # A manual service can expose the same target as a detected app (the
    # detection list deduplicates by target). Match by target too so the app
    # row does not offer to open a second forward for an already open target.
    by_target = {
        (
            str(e.get("target_ip") or ""),
            int(e.get("target_port") or 0),
            str(e.get("protocol") or "tcp"),
        ): e
        for e in config.get("exposures", [])
    }
    result = []
    for svc in detect_cached():
        item = dict(svc)
        exposure = by_service.get((svc["id"], svc["target_port"], svc.get("protocol", "tcp")))
        if exposure is None:
            exposure = by_target.get(
                (
                    str(svc.get("target_ip") or ""),
                    int(svc.get("target_port") or 0),
                    str(svc.get("protocol") or "tcp"),
                )
            )
        item["exposed"] = exposure is not None
        item["exposure_enabled"] = bool(exposure.get("enabled", True)) if exposure else False
        item["exposure_id"] = exposure.get("id") if exposure else ""
        item["exposure_error"] = bool(exposure.get("sync_error")) if exposure else False
        item["public_port"] = int(exposure.get("public_port", 0)) if exposure else 0
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
    service_id = str(body.get("service_id") or "")
    service = service_by_id(service_id)
    if not service:
        # The detection cache can be up to 15 seconds old. A service that just
        # appeared (or a manual entry hidden by target deduplication) must not
        # fail with service_not_found.
        detect_cached(force=True)
        service = service_by_id(service_id)
    if not service and service_id.startswith("manual:"):
        parts = service_id.split(":")
        if len(parts) >= 2:
            item = _manual_service(state.load(), parts[1])
            service = detect.manual_entry(item) if item else None
    if not service:
        return api_error("service_not_found", 404)
    if service.get("protocol", "tcp") != "tcp":
        return api_error("unsupported_protocol", 400)

    try:
        requested_port = _requested_public_port(body)
    except ValueError as exc:
        return api_error(str(exc), 400)

    with _sync_lock:
        with state.LOCK:
            config = state.load()
            try:
                exposure, port_changed, existing = _create_or_open_exposure(
                    config,
                    service,
                    str(body.get("name") or ""),
                    requested_port,
                )
            except ValueError as exc:
                code = str(exc)
                return api_error(code, 409 if code == "no_public_port" else 400)
            state.save(config)

        saved, result = _sync_exposure(exposure["id"])
        if saved is None:
            return api_error("exposure_not_found", 404)

    payload = {
        "ok": not result.get("errors"),
        "existing": existing,
        "port_changed": port_changed or bool(result.get("retried_public_port")),
        "requested_public_port": requested_port,
        "exposure": exposure_view(saved),
        "sync": present_sync(result),
    }
    return jsonify(payload), 200 if existing else 201


@app.patch("/api/exposures/<exposure_id>")
def update_exposure(exposure_id: str):
    body = request.get_json(silent=True) or {}
    requested_port = None
    with _sync_lock:
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
                requested_port = public_port
            if "enabled" in body:
                if body["enabled"] and str(exposure.get("protocol") or "tcp") != "tcp":
                    return api_error("unsupported_protocol", 400)
                exposure["enabled"] = bool(body["enabled"])
            if "name" in body and str(body["name"]).strip():
                exposure["name"] = str(body["name"]).strip()[:80]
            exposure["vps_name"] = sync.vps_name(exposure)
            state.save(config)

        # A public port already used on the VPS is retried on a free one, the
        # same way a new manual service is opened.
        saved, result = _sync_exposure(exposure_id)

    if saved is None:
        return api_error("exposure_not_found", 404)
    return jsonify(
        {
            "ok": not result.get("errors"),
            "port_changed": bool(result.get("retried_public_port")),
            "requested_public_port": requested_port,
            "exposure": exposure_view(saved),
            "sync": present_sync(result),
        }
    )


@app.post("/api/exposures/<exposure_id>/retry")
def retry_exposure(exposure_id: str):
    with _sync_lock:
        exposure, result = _sync_exposure(exposure_id)
    if exposure is None:
        return api_error("exposure_not_found", 404)
    return jsonify(
        {
            "ok": not result.get("errors"),
            "exposure": exposure_view(exposure),
            "sync": present_sync(result),
        }
    )


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


@app.get("/api/bootstrap")
def get_bootstrap():
    config = state.load()
    bootstrap = config.get("bootstrap") or {}
    if state.paired(config) or not bootstrap:
        return jsonify({"active": False})
    return jsonify(bootstrap_view(bootstrap))


@app.post("/api/bootstrap")
def create_bootstrap():
    body = request.get_json(silent=True) or {}
    with state.LOCK:
        config = state.load()
        if state.paired(config):
            return api_error("already_paired", 409)
        try:
            bootstrap = build_bootstrap(body, config.get("bootstrap") or {})
        except BootstrapError as exc:
            return api_error(exc.code, 400, **exc.params)
        config["bootstrap"] = bootstrap
        state.save(config)
    return jsonify(bootstrap_view(bootstrap))


@app.delete("/api/bootstrap")
def delete_bootstrap():
    with state.LOCK:
        config = state.load()
        config["bootstrap"] = {}
        state.save(config)
    return jsonify({"ok": True})


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
        bootstrap = config.get("bootstrap") or {}
        if bootstrap:
            field = bootstrap_mismatch(payload, bootstrap)
            if field:
                return api_error("pair_bootstrap_mismatch", 400, field=field)
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
        config["bootstrap"] = {}
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

    last_error: VPSError | None = None
    with state.LOCK:
        config = state.load()
        # The first API request triggers the WireGuard handshake, so allow a
        # few seconds before declaring the registration failed.
        for attempt in range(4):
            try:
                ensure_peer(config, public)
                last_error = None
                break
            except VPSError as exc:
                last_error = exc
                if attempt < 3:
                    time.sleep(1)
        state.save(config)

    if last_error is not None:
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
                    "detail": str(last_error),
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
    with state.LOCK:
        current = state.load()
        current.setdefault("vps", {})["peer_registered"] = True
        state.save(current)
    return jsonify({"ok": True, "public_key": public})


@app.post("/api/unpair")
def unpair():
    # Network calls happen without the state lock: status/services polling
    # must keep working while the VPS is slow or unreachable.
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
    with state.LOCK:
        config = state.load()
        config["vps"] = {}
        config["bootstrap"] = {}
        for exposure in config.get("exposures", []):
            exposure["vps_forward_id"] = None
            exposure["sync_error"] = ""
            exposure["sync_error_status"] = None
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
    config = state.load()
    return jsonify(
        [manual_service_view(item, config) for item in (config.get("manual_services") or [])]
    )


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

    wants_open = bool(body.get("open"))
    if wants_open and protocol != "tcp":
        return api_error("unsupported_protocol", 400)
    try:
        requested_port = _requested_public_port(body) if wants_open else None
    except ValueError as exc:
        return api_error(str(exc), 400)

    with _sync_lock:
        with state.LOCK:
            config = state.load()
            entry = next(
                (
                    item
                    for item in (config.get("manual_services") or [])
                    if str(item.get("host")) == host
                    and int(item.get("port") or 0) == port
                    and str(item.get("protocol") or "tcp") == protocol
                ),
                None,
            )
            created = entry is None
            if created:
                entry = {
                    "id": uuid.uuid4().hex[:8],
                    "name": name or f"{host}:{port}",
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                }
                config.setdefault("manual_services", []).append(entry)
                state.save(config)

        detect_cached(force=True)
        exposure = None
        result = None
        port_changed = False
        existing = False
        if wants_open:
            service = detect.manual_entry(entry)
            if service is None:
                return api_error("invalid_manual_service", 400)
            with state.LOCK:
                config = state.load()
                try:
                    exposure, port_changed, existing = _create_or_open_exposure(
                        config, service, str(entry.get("name") or ""), requested_port
                    )
                except ValueError as exc:
                    code = str(exc)
                    return api_error(code, 409 if code == "no_public_port" else 400)
                state.save(config)
            exposure, result = _sync_exposure(exposure["id"])

    payload = {
        "ok": True,
        "created": created,
        "existing": existing,
        "manual_service": manual_service_view(entry),
        "port_changed": port_changed or bool(result and result.get("retried_public_port")),
        "requested_public_port": requested_port,
        "sync": present_sync(result) if result else None,
    }
    if exposure is not None:
        payload["exposure"] = exposure_view(exposure)
        payload["ok"] = not result.get("errors")
    return jsonify(payload), 201


@app.post("/api/manual-services/<service_id>/open")
def open_manual_service(service_id: str):
    body = request.get_json(silent=True) or {}
    try:
        requested_port = _requested_public_port(body)
    except ValueError as exc:
        return api_error(str(exc), 400)

    with _sync_lock:
        config = state.load()
        item = _manual_service(config, service_id)
        if item is None:
            return api_error("manual_service_not_found", 404)
        if str(item.get("protocol") or "tcp") != "tcp":
            return api_error("unsupported_protocol", 400)
        service = detect.manual_entry(item)
        if service is None:
            return api_error("invalid_manual_service", 400)
        with state.LOCK:
            config = state.load()
            try:
                exposure, port_changed, existing = _create_or_open_exposure(
                    config, service, str(item.get("name") or ""), requested_port
                )
            except ValueError as exc:
                code = str(exc)
                return api_error(code, 409 if code == "no_public_port" else 400)
            state.save(config)
        exposure, result = _sync_exposure(exposure["id"])

    return jsonify(
        {
            "ok": not result.get("errors"),
            "existing": existing,
            "port_changed": port_changed or bool(result.get("retried_public_port")),
            "requested_public_port": requested_port,
            "manual_service": manual_service_view(item),
            "exposure": exposure_view(exposure) if exposure else None,
            "sync": present_sync(result),
        }
    )


@app.delete("/api/manual-services/<service_id>")
def delete_manual_service(service_id: str):
    with _sync_lock:
        with state.LOCK:
            config = state.load()
            if any(
                str(exposure.get("service_id", "")).startswith(f"manual:{service_id}:")
                for exposure in config.get("exposures", [])
            ):
                return api_error("manual_service_in_use", 409)
            before = len(config.get("manual_services") or [])
            config["manual_services"] = [
                item
                for item in (config.get("manual_services") or [])
                if item.get("id") != service_id
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

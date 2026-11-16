"""Registro de auditoría local con cadena de hashes.

Cada acción sensible se añade a ``data/audit.log`` (JSONL, 0600). La entrada
incluye el hash de la anterior, de modo que borrar o alterar una línea rompe la
cadena y ``verify()`` lo detecta.

No sustituye a un sistema de logging externo ni protege frente a root: si un
atacante controla el host puede reescribir el archivo completo. Su objetivo es
detectar manipulaciones accidentales o parciales y dejar trazabilidad de las
operaciones del panel.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("UMBREL_TUNNEL_DATA", "/data"))
AUDIT_FILE = DATA_DIR / "audit.log"
ROTATED_FILE = DATA_DIR / "audit.log.1"
MAX_BYTES = 1 << 20
GENESIS = "0" * 64

_SECRET_HINTS = ("token", "password", "secret", "private", "key")
_lock = threading.Lock()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _redact(value: object) -> object:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            name = str(key).lower()
            if any(hint in name for hint in _SECRET_HINTS):
                result[key] = "***"
            else:
                result[key] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and value.startswith("ut1."):
        return "***"
    return value


def _last_hash() -> str:
    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
    except OSError:
        return GENESIS
    if not lines:
        return GENESIS
    try:
        parsed = json.loads(lines[-1])
    except ValueError:
        return GENESIS
    value = parsed.get("hash")
    if isinstance(value, str) and len(value) == 64:
        return value
    return GENESIS


def _rotate_if_needed() -> None:
    try:
        if AUDIT_FILE.stat().st_size < MAX_BYTES:
            return
    except OSError:
        return
    try:
        os.replace(AUDIT_FILE, ROTATED_FILE)
        os.chmod(ROTATED_FILE, 0o600)
    except OSError:
        # Si no se puede rotar, seguir escribiendo es preferible a perder el
        # evento; el archivo crecerá por encima del límite.
        return


def _request_context() -> tuple[str, str]:
    try:
        from flask import has_request_context, request, session
    except Exception:  # pragma: no cover - Flask always exists in the app
        return "", ""
    if not has_request_context():
        return "", ""
    ip = str(request.remote_addr or "")
    actor = "panel" if session.get("auth") else "anonymous"
    return actor, ip


def log(event: str, **details: object) -> None:
    """Añade un evento. Nunca lanza: la auditoría no debe romper la petición."""
    actor = str(details.pop("actor", "") or "")
    ip = str(details.pop("ip", "") or "")
    if not actor or not ip:
        request_actor, request_ip = _request_context()
        actor = actor or request_actor
        ip = ip or request_ip

    record = {
        "v": 1,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": str(event)[:64],
        "actor": actor[:32],
        "ip": ip[:64],
        "details": _redact(details),
    }

    with _lock:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            _rotate_if_needed()
            prev = _last_hash()
            record["prevHash"] = prev
            digest = hashlib.sha256((prev + _canonical(record)).encode("utf-8")).hexdigest()
            line = _canonical({**record, "hash": digest}) + "\n"
            fd = os.open(AUDIT_FILE, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    handle.write(line)
            finally:
                try:
                    os.chmod(AUDIT_FILE, 0o600)
                except OSError:
                    pass
        except (OSError, ValueError, TypeError):
            return


def verify() -> dict:
    """Comprueba la cadena del archivo activo."""
    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
    except FileNotFoundError:
        return {"ok": True, "entries": 0, "reason": "empty"}
    except OSError as exc:
        return {"ok": False, "entries": 0, "reason": f"read_error: {exc}"}

    prev = GENESIS
    for index, line in enumerate(lines, start=1):
        try:
            parsed = json.loads(line)
        except ValueError:
            return {"ok": False, "entries": index - 1, "reason": f"invalid_json:{index}"}
        if not isinstance(parsed, dict):
            return {"ok": False, "entries": index - 1, "reason": f"invalid_entry:{index}"}
        digest = parsed.pop("hash", None)
        if parsed.get("prevHash") != prev:
            return {"ok": False, "entries": index - 1, "reason": f"prev_hash:{index}"}
        expected = hashlib.sha256((prev + _canonical(parsed)).encode("utf-8")).hexdigest()
        if digest != expected:
            return {"ok": False, "entries": index - 1, "reason": f"hash:{index}"}
        prev = digest
    return {"ok": True, "entries": len(lines), "reason": "ok"}

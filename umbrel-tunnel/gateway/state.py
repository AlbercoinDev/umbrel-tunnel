"""Estado persistente del gateway de Umbrel."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
from pathlib import Path

DATA_DIR = Path(os.environ.get("UMBREL_TUNNEL_DATA", "/data"))
CONFIG_FILE = DATA_DIR / "config.json"
BACKUP_FILE = DATA_DIR / "config.json.bak"
SESSION_KEY_FILE = DATA_DIR / "session.key"
LOCK = threading.RLock()

DEFAULT = {
    "vps": {},
    "bootstrap": {},
    "exposures": [],
    "manual_services": [],
    "settings": {
        "base_domain": "",
        "sync_interval": 30,
        "tunnel_port_start": 20000,
        "tunnel_port_end": 29999,
    },
}


def _merge_defaults(data: dict) -> dict:
    merged = json.loads(json.dumps(DEFAULT))
    merged.update(data or {})
    settings = dict(DEFAULT["settings"])
    settings.update((data or {}).get("settings") or {})
    merged["settings"] = settings
    if not isinstance(merged.get("exposures"), list):
        merged["exposures"] = []
    if not isinstance(merged.get("manual_services"), list):
        merged["manual_services"] = []
    if not isinstance(merged.get("vps"), dict):
        merged["vps"] = {}
    if not isinstance(merged.get("bootstrap"), dict):
        merged["bootstrap"] = {}
    return merged


class StateError(RuntimeError):
    """config.json exists but cannot be read; never replace it with defaults."""


def _read(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config.json no es un objeto JSON")
    return data


def load() -> dict:
    """Load the persistent state.

    A missing file is a fresh install. An unreadable or corrupt file is not:
    returning defaults would make the next ``save()`` erase the VPS pairing,
    token and publications. Fall back to the last good copy, or fail loudly.
    """
    with LOCK:
        try:
            return _merge_defaults(_read(CONFIG_FILE))
        except FileNotFoundError:
            return _merge_defaults({})
        except (OSError, ValueError) as exc:  # JSONDecodeError is a ValueError
            primary = exc
        try:
            return _merge_defaults(_read(BACKUP_FILE))
        except (OSError, ValueError) as exc:
            raise StateError(
                f"{CONFIG_FILE} no se puede leer ({primary}) y no hay copia válida "
                f"en {BACKUP_FILE} ({exc}); revisa el archivo antes de continuar"
            ) from primary


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".config-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def save(config: dict) -> None:
    with LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        _atomic_write(CONFIG_FILE, text)
        # Last known-good copy, used by load() if config.json gets corrupted.
        _atomic_write(BACKUP_FILE, text)


def session_secret() -> str:
    """Stable per-install secret used to sign the login cookie."""
    with LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            value = SESSION_KEY_FILE.read_text(encoding="ascii").strip()
            if len(value) >= 64:
                return value
        except OSError:
            pass
        value = secrets.token_hex(32)
        fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".session-", suffix=".key")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(value + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, SESSION_KEY_FILE)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return value


def paired(config: dict) -> bool:
    vps = config.get("vps") or {}
    return bool(vps.get("api") and vps.get("token"))


def find_exposure(config: dict, exposure_id: str) -> dict | None:
    for exposure in config.get("exposures", []):
        if exposure.get("id") == exposure_id:
            return exposure
    return None

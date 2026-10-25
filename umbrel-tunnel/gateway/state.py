"""Estado persistente del gateway de Umbrel."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

DATA_DIR = Path("/data")
CONFIG_FILE = DATA_DIR / "config.json"
LOCK = threading.RLock()

DEFAULT = {
    "vps": {},
    "exposures": [],
    "settings": {
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
    if not isinstance(merged.get("vps"), dict):
        merged["vps"] = {}
    return merged


def load() -> dict:
    with LOCK:
        try:
            raw = CONFIG_FILE.read_text(encoding="utf-8")
            return _merge_defaults(json.loads(raw))
        except FileNotFoundError:
            return _merge_defaults({})
        except (OSError, json.JSONDecodeError):
            return _merge_defaults({})


def save(config: dict) -> None:
    with LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".config-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, CONFIG_FILE)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def paired(config: dict) -> bool:
    vps = config.get("vps") or {}
    return bool(vps.get("api") and vps.get("token"))


def find_exposure(config: dict, exposure_id: str) -> dict | None:
    for exposure in config.get("exposures", []):
        if exposure.get("id") == exposure_id:
            return exposure
    return None

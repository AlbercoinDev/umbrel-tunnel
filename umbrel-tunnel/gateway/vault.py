"""Cifrado en reposo de los secretos del gateway (AES-256-GCM).

Los archivos que contienen credenciales (``config.json``, la clave privada de
WireGuard, la copia persistente de ``wg0.conf`` y la rotación pendiente) se
guardan como un sobre JSON cifrado. La clave de 256 bits vive en
``data/secrets.key`` con permisos ``0600`` y se deriva con scrypt; viaja junto
a los datos para que una restauración de Umbrel siga funcionando.

Alcance: protege copias parciales o lectura accidental de un archivo suelto.
Quien pueda leer todo el directorio de datos (o una copia completa de él)
también obtiene la clave; el aislamiento real frente a eso es el cifrado del
disco y los permisos de Umbrel.

Formato del sobre (texto JSON, una línea)::

    {"v":1,"a":"A256GCM","n":"<nonce b64>","c":"<ciphertext+tag b64>"}

Cualquier archivo que no sea un sobre válido se trata como texto plano legado,
de modo que una actualización migra sin perder datos ni el emparejamiento.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import tempfile
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA_DIR = Path(os.environ.get("UMBREL_TUNNEL_DATA", "/data"))
KEY_FILE = DATA_DIR / "secrets.key"

SALT = b"umbrel-tunnel/secrets/v1"
AAD = b"umbrel-tunnel/v1"
VERSION = 1
KDF_N = 1 << 14
KDF_R = 8
KDF_P = 1
KDF_MAXMEM = 64 * 1024 * 1024

_LOCK = threading.RLock()
_KEY: bytes | None = None
_LOGGER = logging.getLogger("umbrel-tunnel.secrets")


class SecretsError(RuntimeError):
    """El sobre existe pero no se puede descifrar (clave distinta o corrupto)."""


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".secret-", suffix=".tmp")
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


def _load_seed() -> bytes:
    try:
        raw = KEY_FILE.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        seed = os.urandom(32)
        _atomic_write(KEY_FILE, seed.hex() + "\n")
        _LOGGER.info("clave de cifrado creada en %s", KEY_FILE)
        return seed
    except OSError as exc:
        # No se puede leer: crear otra destruiría la capacidad de descifrar.
        raise SecretsError(f"no se puede leer {KEY_FILE}: {exc}") from exc
    try:
        seed = bytes.fromhex(raw)
    except ValueError as exc:
        raise SecretsError(f"{KEY_FILE} no contiene una clave válida") from exc
    if len(seed) < 32:
        raise SecretsError(f"{KEY_FILE} contiene una clave demasiado corta")
    return seed


def key() -> bytes:
    """Clave AES derivada de ``secrets.key`` (se calcula una vez por proceso)."""
    global _KEY
    with _LOCK:
        if _KEY is None:
            seed = _load_seed()
            _KEY = hashlib.scrypt(
                seed,
                salt=SALT,
                n=KDF_N,
                r=KDF_R,
                p=KDF_P,
                dklen=32,
                maxmem=KDF_MAXMEM,
            )
        return _KEY


def is_envelope(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped.startswith("{"):
        return False
    try:
        data = json.loads(stripped)
    except ValueError:
        return False
    return (
        isinstance(data, dict)
        and data.get("v") == VERSION
        and data.get("a") == "A256GCM"
        and isinstance(data.get("n"), str)
        and isinstance(data.get("c"), str)
    )


def encrypt(text: str) -> str:
    nonce = os.urandom(12)
    sealed = AESGCM(key()).encrypt(nonce, text.encode("utf-8"), AAD)
    envelope = {
        "v": VERSION,
        "a": "A256GCM",
        "n": base64.b64encode(nonce).decode("ascii"),
        "c": base64.b64encode(sealed).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":")) + "\n"


def decrypt(text: str) -> str:
    try:
        envelope = json.loads(text)
        nonce = base64.b64decode(envelope["n"], validate=True)
        sealed = base64.b64decode(envelope["c"], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        raise SecretsError("sobre cifrado inválido") from exc
    try:
        return AESGCM(key()).decrypt(nonce, sealed, AAD).decode("utf-8")
    except InvalidTag as exc:
        raise SecretsError(
            "no se puede descifrar: falta data/secrets.key o no coincide"
        ) from exc
    except ValueError as exc:
        raise SecretsError("contenido cifrado corrupto") from exc


def read_text(path: Path) -> str:
    """Lee un archivo descifrándolo si es un sobre; texto plano si es legado."""
    text = path.read_text(encoding="utf-8")
    return decrypt(text) if is_envelope(text) else text


def write_text(path: Path, text: str) -> None:
    """Escribe el texto como sobre cifrado con permisos 0600."""
    _atomic_write(path, encrypt(text))


def rewrite_if_plaintext(path: Path) -> bool:
    """Cifra un archivo legado en el sitio. Devuelve True si lo migró."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if is_envelope(text):
        return False
    write_text(path, text)
    return True

"""Small dependency-free i18n layer for the Umbrel gateway.

Language resolution order on the first visit:
1. explicit ``?lang=`` parameter
2. ``ut_lang`` cookie
3. ``Accept-Language`` (the browser/OS language reported by UmbrelOS)
4. ``UMBREL_LANG`` / ``LANG`` environment variables, when meaningful
5. Spanish, the project default

The UI defaults to Spanish and offers English from the header and the login
page. Translations live in ``i18n/<code>.json`` and are flat key/value maps.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT = "es"
SUPPORTED = ("es", "en")
I18N_DIR = Path(__file__).with_name("i18n")
_cache: dict[str, dict[str, str]] = {}


def _load(lang: str) -> dict[str, str]:
    if lang not in SUPPORTED:
        lang = DEFAULT
    if lang not in _cache:
        try:
            _cache[lang] = json.loads((I18N_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _cache[lang] = {}
    return _cache[lang]


def catalog(lang: str) -> dict[str, str]:
    """Return the merged catalog (requested language over Spanish fallback)."""
    merged = dict(_load(DEFAULT))
    merged.update(_load(lang))
    return merged


def translate(lang: str, key: str, **params: object) -> str:
    text = catalog(lang).get(key) or _load(DEFAULT).get(key) or key
    try:
        return text.format(**params)
    except (KeyError, IndexError, ValueError):
        return text


def _from_env() -> str | None:
    for name in ("UMBREL_LANG", "LANG", "LC_ALL"):
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        code = raw.split(".", 1)[0].split("_", 1)[0].lower()
        if code in SUPPORTED:
            return code
    return None


def _from_accept_language(header: str) -> str | None:
    # Respect q-values enough for the common "es-ES,es;q=0.9,en;q=0.8" case.
    candidates: list[tuple[float, str]] = []
    for part in (header or "").split(","):
        pieces = part.strip().split(";")
        if not pieces or not pieces[0]:
            continue
        q = 1.0
        for piece in pieces[1:]:
            piece = piece.strip()
            if piece.startswith("q="):
                try:
                    q = float(piece[2:])
                except ValueError:
                    q = 0.0
        code = pieces[0].strip().lower().split("-", 1)[0]
        if code in SUPPORTED:
            candidates.append((q, code))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def resolve(request) -> str:
    query = (request.args.get("lang") or "").strip().lower()
    if query in SUPPORTED:
        return query
    cookie = (request.cookies.get("ut_lang") or "").strip().lower()
    if cookie in SUPPORTED:
        return cookie
    header = _from_accept_language(request.headers.get("Accept-Language", ""))
    if header:
        return header
    env = _from_env()
    if env:
        return env
    return DEFAULT

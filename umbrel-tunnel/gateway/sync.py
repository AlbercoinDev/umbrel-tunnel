"""Sincronización declarativa entre las exposiciones de Umbrel y el VPS.

El VPS es quien abre los puertos públicos (DNAT). La app de Umbrel guarda lo
que el usuario quiere exponer y reconcilia: crea, actualiza y elimina forwards
en la API del VPS, y reconfigura HAProxy en el lado de Umbrel.
"""

from __future__ import annotations

import re
import time

import proxy
import wireguard
from vps import VPSClient, VPSError

NAME_PREFIX = "umbrel:"


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value or "").strip("-")
    return cleaned[:32] or "servicio"


def vps_name(exposure: dict) -> str:
    if exposure.get("vps_name"):
        return exposure["vps_name"]
    unique = str(exposure.get("id", ""))[:6] or "000000"
    return f"{NAME_PREFIX}{_slug(exposure.get('name', 'servicio'))}:{unique}"[:64]


def payload(exposure: dict) -> dict:
    # The VPS always DNATs to the Umbrel peer (10.0.0.2 by default), never to
    # the app container IP: HAProxy on the Umbrel side does the last hop.
    return {
        "name": vps_name(exposure),
        "public_port": int(exposure["public_port"]),
        "target_ip": exposure.get("tunnel_ip") or "10.0.0.2",
        "target_port": int(exposure["tunnel_port"]),
        "protocol": str(exposure.get("protocol") or "tcp"),
        "enabled": True,
    }


def _same(remote: dict, desired: dict) -> bool:
    return (
        int(remote.get("public_port", 0)) == desired["public_port"]
        and remote.get("target_ip") == desired["target_ip"]
        and int(remote.get("target_port", 0)) == desired["target_port"]
        and (remote.get("protocol") or "tcp") == desired["protocol"]
        and bool(remote.get("enabled", True)) is True
    )


def remove_all(config: dict) -> None:
    """Elimina del VPS todos los forwards creados por esta app."""
    vps = config.get("vps") or {}
    if not (vps.get("api") and vps.get("token")):
        return
    try:
        client = VPSClient(vps["api"], vps["token"])
        for forward in client.list_forwards():
            if str(forward.get("name", "")).startswith(NAME_PREFIX):
                client.delete_forward(forward["id"])
    except VPSError:
        pass


def _mark_error(exposure: dict, message: str, status: int | None = None) -> None:
    exposure["sync_error"] = message
    exposure["sync_error_status"] = status
    exposure["last_sync"] = time.time()


def _clear_error(exposure: dict) -> None:
    exposure["sync_error"] = ""
    exposure["sync_error_status"] = None
    exposure.pop("proxy_error", None)


def _strip_proxy_error(exposure: dict) -> None:
    """Remove a previous local proxy failure without touching VPS errors.

    ``sync_error_status`` carries the HTTP status of the VPS failure (a 409 is
    retried on a free public port). Replacing the whole error here used to wipe
    that status, so the automatic retry never ran.
    """
    previous = str(exposure.pop("proxy_error", "") or "")
    if not previous:
        return
    current = str(exposure.get("sync_error") or "")
    if current == previous:
        _clear_error(exposure)
    elif current.endswith(f"; {previous}"):
        exposure["sync_error"] = current[: -len(f"; {previous}")]


def _mark_proxy_error(exposure: dict, message: str) -> None:
    exposure["proxy_error"] = message
    current = str(exposure.get("sync_error") or "")
    if current and not current.startswith("proxy local:"):
        # Keep the VPS error as the primary reason: it is the one the retry
        # logic understands.
        exposure["sync_error"] = f"{current}; {message}"
        exposure["last_sync"] = time.time()
    else:
        _mark_error(exposure, message)


def _mark_all(config: dict, message: str, status: int | None = None) -> None:
    for exposure in config.get("exposures", []):
        _mark_error(exposure, message, status)


def sync(config: dict) -> dict:
    result = {
        "ok": False,
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "errors": [],
        "vps_status": None,
        "at": time.time(),
    }
    vps = config.get("vps") or {}
    if not (vps.get("api") and vps.get("token")):
        message = "no emparejado con un VPS"
        result["errors"].append(message)
        _mark_all(config, message)
        _apply_proxy(config, result)
        return result

    client = VPSClient(vps["api"], vps["token"])
    try:
        remote = client.list_forwards()
        result["vps_status"] = client.status()
    except VPSError as exc:
        # Every exposure is unverified when the VPS cannot be reached. Keeping
        # the old "synchronized" badge would hide the real failure.
        result["errors"].append(str(exc))
        _mark_all(config, str(exc), exc.status)
        _apply_proxy(config, result)
        return result

    by_id = {str(f.get("id")): f for f in remote}
    by_name = {str(f.get("name")): f for f in remote}
    desired_names: set[str] = set()
    # Remote forwards already handled by an exposure. The cleanup pass must not
    # touch them again: a disabled exposure is deleted here, and an updated
    # forward keeps its id even if its name changed.
    handled_ids: set[str] = set()

    tunnel_ip = str(vps.get("umbrel_ip") or "10.0.0.2")
    for exposure in config.get("exposures", []):
        # The Umbrel tunnel address can change if the VPS is re-paired.
        exposure["tunnel_ip"] = tunnel_ip
        exposure["vps_name"] = vps_name(exposure)
        if not exposure.get("enabled", True):
            forward_id = str(exposure.get("vps_forward_id") or "")
            if forward_id:
                handled_ids.add(forward_id)
            if forward_id and forward_id in by_id:
                try:
                    client.delete_forward(forward_id)
                    result["deleted"] += 1
                except VPSError as exc:
                    if exc.status != 404:
                        _mark_error(exposure, str(exc), exc.status)
                        result["errors"].append(f"{exposure.get('name')}: {exc}")
                        continue
            exposure["vps_forward_id"] = None
            _clear_error(exposure)
            exposure["last_sync"] = time.time()
            continue

        desired = payload(exposure)
        desired_names.add(desired["name"])
        current = by_id.get(str(exposure.get("vps_forward_id") or "")) or by_name.get(desired["name"])
        if current is not None:
            handled_ids.add(str(current.get("id")))
        try:
            if current is None:
                created = client.create_forward(desired)
                exposure["vps_forward_id"] = created.get("id")
                result["created"] += 1
            else:
                exposure["vps_forward_id"] = current.get("id")
                if not _same(current, desired):
                    client.update_forward(current["id"], desired)
                    result["updated"] += 1
            _clear_error(exposure)
        except VPSError as exc:
            _mark_error(exposure, str(exc), exc.status)
            result["errors"].append(f"{exposure.get('name')}: {exc}")
        exposure["last_sync"] = time.time()

    # Borra forwards nuestros que ya no corresponden a ninguna exposición.
    for forward in remote:
        forward_id = str(forward.get("id", ""))
        name = str(forward.get("name", ""))
        if forward_id in handled_ids:
            continue
        if not name.startswith(NAME_PREFIX) or name in desired_names:
            continue
        try:
            client.delete_forward(forward_id)
            result["deleted"] += 1
        except VPSError as exc:
            if exc.status != 404:
                result["errors"].append(f"limpieza {name}: {exc}")

    _apply_proxy(config, result)
    result["ok"] = not result["errors"]
    return result


def _apply_proxy(config: dict, result: dict) -> None:
    # HAProxy only proxies TCP. UDP forwards are created from the VPS CLI,
    # where the operator can point them at a UDP listener directly.
    enabled = [
        e
        for e in config.get("exposures", [])
        if e.get("enabled", True) and str(e.get("protocol") or "tcp") == "tcp"
    ]
    # A previous local proxy failure must not survive a successful apply.
    for exposure in enabled:
        _strip_proxy_error(exposure)
    if not enabled:
        try:
            proxy.stop()
        except Exception as exc:  # noqa: BLE001 - se reporta, no rompe el sync
            result["errors"].append(f"proxy local: {exc}")
        return
    bind_ip = wireguard.address() or "10.0.0.2"
    try:
        proxy.apply(enabled, bind_ip)
    except proxy.ProxyError as exc:
        message = f"proxy local: {exc}"
        result["errors"].append(message)
        # The VPS DNAT can be perfectly healthy and the service still be
        # unreachable when HAProxy fails. Mark the exposure instead of showing
        # a misleading "synchronized" badge.
        for exposure in enabled:
            _mark_proxy_error(exposure, message)

"""Cliente de la API de umbrel-tunnel en el VPS (siempre a través del túnel)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class VPSError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class VPSClient:
    def __init__(self, api: str, token: str, timeout: float = 6.0):
        self.api = api.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
        data = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "umbrel-tunnel-umbrel",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.api + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                if not body:
                    return None
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            try:
                message = json.loads(body).get("error", body)
            except (json.JSONDecodeError, AttributeError):
                message = body
            raise VPSError(f"VPS HTTP {exc.code}: {message}", status=exc.code) from exc
        except urllib.error.URLError as exc:
            raise VPSError(f"no se pudo contactar con el VPS: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise VPSError(f"error de red con el VPS: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise VPSError(f"respuesta inválida del VPS: {exc}") from exc

    def health(self) -> dict:
        return self._request("GET", "/health")

    def status(self) -> dict:
        return self._request("GET", "/api/status")

    def list_forwards(self) -> list[dict]:
        data = self._request("GET", "/api/forwards")
        return data if isinstance(data, list) else []

    def create_forward(self, forward: dict) -> dict:
        return self._request("POST", "/api/forwards", forward)

    def update_forward(self, forward_id: str, patch: dict) -> dict:
        return self._request("PATCH", f"/api/forwards/{forward_id}", patch)

    def delete_forward(self, forward_id: str) -> None:
        self._request("DELETE", f"/api/forwards/{forward_id}")

    def list_peers(self) -> list[dict]:
        data = self._request("GET", "/api/peers")
        return data if isinstance(data, list) else []

    def create_peer(self, peer: dict) -> dict:
        return self._request("POST", "/api/peers", peer)

    def update_peer(self, peer_id: str, patch: dict) -> dict:
        return self._request("PUT", f"/api/peers/{peer_id}", patch)

    def delete_peer(self, peer_id: str) -> None:
        self._request("DELETE", f"/api/peers/{peer_id}")

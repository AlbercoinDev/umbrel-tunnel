"""Cliente mínimo de la API de Docker.

Se conecta al socket-proxy (TCP) o directamente al socket Unix. Solo usa la
biblioteca estándar para no añadir dependencias al contenedor.
"""

from __future__ import annotations

import http.client
import json
import os
import socket


class DockerError(RuntimeError):
    pass


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 5.0):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


class DockerClient:
    def __init__(self, docker_host: str | None = None, timeout: float = 5.0):
        self.host = docker_host or os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
        self.timeout = timeout

    def _connection(self) -> http.client.HTTPConnection:
        if self.host.startswith("unix://"):
            return _UnixHTTPConnection(self.host[len("unix://") :], self.timeout)
        if self.host.startswith("tcp://"):
            netloc = self.host[len("tcp://") :]
            host, _, port = netloc.partition(":")
            return http.client.HTTPConnection(host, int(port or 2375), timeout=self.timeout)
        return http.client.HTTPConnection(self.host, timeout=self.timeout)

    def get(self, path: str):
        conn = self._connection()
        try:
            conn.request("GET", path, headers={"Host": "docker"})
            resp = conn.getresponse()
            data = resp.read()
            if resp.status >= 400:
                raise DockerError(f"Docker HTTP {resp.status}: {data[:200]!r}")
            if not data:
                return None
            return json.loads(data)
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
            raise DockerError(f"no se pudo hablar con Docker: {exc}") from exc
        finally:
            conn.close()

    def containers(self) -> list[dict]:
        data = self.get("/containers/json?all=0")
        return data if isinstance(data, list) else []

    def inspect(self, container_id: str) -> dict:
        data = self.get(f"/containers/{container_id}/json")
        return data if isinstance(data, dict) else {}

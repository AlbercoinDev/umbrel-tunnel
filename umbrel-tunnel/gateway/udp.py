"""Bounded UDP relay, listening only on the WireGuard address.

Each client gets a connected upstream socket, so replies cannot cross sessions.
DNS is resolved on new sessions, not pinned for the lifetime of a publication.
"""
from __future__ import annotations

import selectors
import socket
import threading
import time

from proxy import ProxyError, _valid_bind_ip, _valid_target

IDLE_SECONDS = 60
MAX_SESSIONS = 512
_lock = threading.RLock()
_selector = selectors.DefaultSelector()
_listeners = {}
_sessions = {}
_thread = None


def _close_session(key):
    upstream, _ = _sessions.pop(key)
    _selector.unregister(upstream)
    upstream.close()


def _run():
    while True:
        # Do not hold the lock while waiting: configuration must remain responsive.
        events = _selector.select(0.2)
        with _lock:
            for event, _ in events:
                sock = event.fileobj
                try:
                    if event.data[0] == "listener":
                        data, client = sock.recvfrom(65535)
                        key = (sock, client)
                        if key not in _sessions:
                            if len(_sessions) >= MAX_SESSIONS:
                                continue
                            host, port = event.data[1]
                            # Resolve outside configuration parsing; failed DNS must
                            # not take down other listeners or the relay thread.
                            address = socket.gethostbyname(host)
                            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            try:
                                upstream.connect((address, port))
                                upstream.setblocking(False)
                                _selector.register(upstream, selectors.EVENT_READ, ("upstream", key))
                            except Exception:
                                upstream.close()
                                raise
                            _sessions[key] = (upstream, time.monotonic())
                        upstream, _ = _sessions[key]
                        upstream.send(data)
                        _sessions[key] = (upstream, time.monotonic())
                    else:
                        key = event.data[1]
                        if key not in _sessions:
                            continue
                        data = sock.recv(65535)
                        key[0].sendto(data, key[1])
                        _sessions[key] = (sock, time.monotonic())
                except OSError:
                    if event.data[0] == "upstream" and event.data[1] in _sessions:
                        _close_session(event.data[1])
            now = time.monotonic()
            for key, (_, last) in list(_sessions.items()):
                if now - last > IDLE_SECONDS:
                    _close_session(key)


def apply(forwards, bind_ip):
    """Prepare new bindings before replacing the working configuration."""
    global _thread
    bind_ip = _valid_bind_ip(bind_ip)
    desired = {}
    for item in forwards:
        if not item.get("enabled", True):
            continue
        port = int(item["tunnel_port"])
        if not 1 <= port <= 65535:
            raise ProxyError("invalid UDP tunnel port")
        desired[(bind_ip, port)] = _valid_target(item["target_ip"], int(item["target_port"]))
    with _lock:
        prepared = {}
        try:
            for address, target in desired.items():
                if address not in _listeners:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    prepared[address] = sock
                    sock.bind(address)
                    sock.setblocking(False)
        except OSError as exc:
            for sock in prepared.values():
                sock.close()
            raise ProxyError(f"UDP bind: {exc}") from exc
        for address, (sock, target) in list(_listeners.items()):
            if address not in desired or desired[address] != target:
                for key in list(_sessions):
                    if key[0] is sock:
                        _close_session(key)
            if address not in desired:
                _selector.unregister(sock)
                sock.close()
                del _listeners[address]
        for address, target in desired.items():
            if address in _listeners:
                sock = _listeners[address][0]
                _selector.modify(sock, selectors.EVENT_READ, ("listener", target))
            else:
                sock = prepared[address]
                _selector.register(sock, selectors.EVENT_READ, ("listener", target))
            _listeners[address] = (sock, target)
        if desired and (_thread is None or not _thread.is_alive()):
            _thread = threading.Thread(target=_run, name="udp-relay", daemon=True)
            _thread.start()


def status():
    with _lock:
        return {"running": bool(_thread and _thread.is_alive()),
                "listeners": len(_listeners), "sessions": len(_sessions),
                "session_limit": MAX_SESSIONS}


def stop():
    apply([], "10.0.0.2")

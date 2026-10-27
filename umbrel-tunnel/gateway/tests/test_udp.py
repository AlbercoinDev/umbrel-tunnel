"""Real loopback datagrams: these tests do not need WireGuard or root."""
import socket
import threading
import time
import unittest
from unittest import mock

import udp
from proxy import ProxyError


class UDPRelayTests(unittest.TestCase):
    def setUp(self):
        udp.stop()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.settimeout(.1)
        self.done = threading.Event()

        def echo():
            while not self.done.is_set():
                try:
                    data, client = self.server.recvfrom(65535)
                    self.server.sendto(data, client)
                except socket.timeout:
                    continue
                except OSError:
                    break
        self.worker = threading.Thread(target=echo, daemon=True)
        self.worker.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.rule = {"tunnel_port": self.port, "target_ip": "localhost",
                     "target_port": self.server.getsockname()[1], "enabled": True}

    def tearDown(self):
        udp.stop()
        self.done.set()
        self.server.close()
        self.worker.join(1)

    def client(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        self.addCleanup(client.close)
        return client

    def test_multiple_clients_and_replies(self):
        udp.apply([self.rule], "127.0.0.1")
        clients = [self.client() for _ in range(5)]
        for index, client in enumerate(clients):
            client.sendto(f"client-{index}".encode(), ("127.0.0.1", self.port))
        for index, client in enumerate(clients):
            self.assertEqual(client.recv(65535), f"client-{index}".encode())
        self.assertEqual(udp.status()["sessions"], 5)

    def test_pause_resume_and_idempotent_apply(self):
        udp.apply([self.rule], "127.0.0.1")
        client = self.client()
        for _ in range(2):
            udp.apply([self.rule], "127.0.0.1")
            client.sendto(b"hello", ("127.0.0.1", self.port))
            self.assertEqual(client.recv(65535), b"hello")
        udp.apply([{**self.rule, "enabled": False}], "127.0.0.1")
        self.assertEqual(udp.status()["listeners"], 0)
        self.assertEqual(udp.status()["sessions"], 0)
        udp.apply([self.rule], "127.0.0.1")
        client.sendto(b"again", ("127.0.0.1", self.port))
        self.assertEqual(client.recv(65535), b"again")

    def test_failed_binding_preserves_working_listener(self):
        udp.apply([self.rule], "127.0.0.1")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
            busy.bind(("127.0.0.1", 0))
            with self.assertRaises(ProxyError):
                udp.apply([self.rule, {**self.rule, "tunnel_port": busy.getsockname()[1]}], "127.0.0.1")
        client = self.client()
        client.sendto(b"still-working", ("127.0.0.1", self.port))
        self.assertEqual(client.recv(65535), b"still-working")

    def test_idle_sessions_expire(self):
        udp.apply([self.rule], "127.0.0.1")
        client = self.client()
        with mock.patch.object(udp, "IDLE_SECONDS", .05):
            client.sendto(b"expire", ("127.0.0.1", self.port))
            self.assertEqual(client.recv(65535), b"expire")
            deadline = time.monotonic() + 2
            while udp.status()["sessions"] and time.monotonic() < deadline:
                self.done.wait(.02)
            self.assertEqual(udp.status()["sessions"], 0)

    def test_session_limit(self):
        udp.apply([self.rule], "127.0.0.1")
        with mock.patch.object(udp, "MAX_SESSIONS", 1):
            first, second = self.client(), self.client()
            first.sendto(b"one", ("127.0.0.1", self.port))
            self.assertEqual(first.recv(65535), b"one")
            second.settimeout(.3)
            second.sendto(b"two", ("127.0.0.1", self.port))
            with self.assertRaises(socket.timeout):
                second.recv(65535)
            self.assertEqual(udp.status()["sessions"], 1)

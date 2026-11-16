"""Destinos manuales: bloquear lo peligroso sin romper servicios legítimos."""

import socket
from unittest import mock

import targets
from test_gateway import unittest


def _resolve(*addresses):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
        for address in addresses
    ]


class TargetValidationTests(unittest.TestCase):
    def assertBlocked(self, host):
        with self.assertRaises(targets.TargetError, msg=host):
            targets.validate(host)

    def test_loopback_and_metadata_are_blocked(self):
        for host in (
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
        ):
            self.assertBlocked(host)

    def test_dns_name_resolving_to_metadata_is_blocked(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("169.254.169.254")
        ):
            self.assertBlocked("metadata.google.internal")

    def test_localhost_name_is_blocked(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("127.0.0.1")
        ):
            self.assertBlocked("localhost")

    def test_private_container_and_lan_addresses_are_allowed(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("10.21.0.7")
        ):
            self.assertEqual(targets.validate("bitcoin_bitcoind_1"), "bitcoin_bitcoind_1")
        self.assertEqual(targets.validate("10.21.0.5"), "10.21.0.5")
        self.assertEqual(targets.validate("172.17.0.2"), "172.17.0.2")
        self.assertEqual(targets.validate("192.168.1.10"), "192.168.1.10")

    def test_public_address_is_not_blocked(self):
        # Un servicio externo puede ser un caso legítimo; el objetivo es impedir
        # loopback/link-local, no convertirse en una allowlist de red privada.
        self.assertEqual(targets.validate("203.0.113.10"), "203.0.113.10")

    def test_unresolved_container_name_is_accepted(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", side_effect=socket.gaierror("not yet")
        ):
            self.assertEqual(targets.validate("new_app_web_1"), "new_app_web_1")

    def test_malformed_hosts_are_rejected(self):
        for host in ("", "   ", "http://10.0.0.2", "user@host", "host name"):
            self.assertBlocked(host)

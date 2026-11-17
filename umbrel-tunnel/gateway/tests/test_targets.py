"""Destinos manuales: bloquear lo peligroso sin romper servicios legítimos."""

import socket
from unittest import mock

import test_gateway as fixtures
import proxy
import state
import targets
from test_gateway import unittest


def _resolve(*addresses):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
        for address in addresses
    ]


class TargetValidationTests(unittest.TestCase):
    def setUp(self):
        targets.clear_cache()
        self.addCleanup(targets.clear_cache)
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

    def test_cgnat_and_metadata_ranges_are_blocked(self):
        for host in ("100.64.0.1", "100.100.100.200", "100.127.255.254"):
            self.assertBlocked(host)
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("100.100.100.200")
        ):
            self.assertBlocked("metadata.internal")

    def test_dns_rebinding_is_caught_on_revalidation(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("10.21.0.7")
        ):
            self.assertEqual(targets.validate("app_web_1"), "app_web_1")
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("127.0.0.1")
        ):
            self.assertBlocked("app_web_1")

    def test_pin_returns_an_approved_ip(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("10.21.0.7")
        ):
            self.assertEqual(targets.pin("app_web_1"), "10.21.0.7")
            # Dentro del TTL no vuelve a resolver: la IP queda fijada.
            with mock.patch.object(
                targets.socket, "getaddrinfo", return_value=_resolve("127.0.0.1")
            ):
                self.assertEqual(targets.pin("app_web_1"), "10.21.0.7")

    def test_pin_fails_closed_when_unresolved(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", side_effect=socket.gaierror("not yet")
        ):
            with self.assertRaises(targets.TargetError):
                targets.pin("new_app_web_1")

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

    def test_external_names_are_classified(self):
        self.assertFalse(targets.is_external_name("10.0.0.5"))
        self.assertFalse(targets.is_external_name("demo_web_1"))
        self.assertTrue(targets.is_external_name("example.com"))
        self.assertTrue(targets.is_external_name("sub.example.com"))

    def test_pin_refresh_uses_the_new_resolution(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("10.21.0.7")
        ):
            self.assertEqual(targets.pin("app.example", refresh=True), "10.21.0.7")
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("10.21.0.8")
        ):
            self.assertEqual(targets.pin("app.example"), "10.21.0.7")
            self.assertEqual(targets.pin("app.example", refresh=True), "10.21.0.8")

    def test_external_name_resolving_to_loopback_is_blocked(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("127.0.0.1")
        ):
            with self.assertRaises(targets.TargetError):
                targets.pin("rebind.example", refresh=True)

    def test_external_dns_is_pinned_in_haproxy(self):
        forwards = [{
            "id": "a1",
            "name": "demo",
            "tunnel_port": 20000,
            "target_ip": "app.example.com",
            "target_port": 8080,
            "enabled": True,
        }]
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("203.0.113.10")
        ):
            config = proxy.render(forwards, "10.0.0.2")
        server = next(line for line in config.splitlines() if "server s1" in line)
        self.assertIn("203.0.113.10:8080", server)
        self.assertNotIn("resolvers docker", server)

    def test_docker_names_keep_the_dynamic_resolver(self):
        forwards = [{
            "id": "b1",
            "name": "demo",
            "tunnel_port": 20001,
            "target_ip": "demo_web_1",
            "target_port": 8080,
            "enabled": True,
        }]
        config = proxy.render(forwards, "10.0.0.2")
        server = next(line for line in config.splitlines() if "server s1" in line)
        self.assertIn("resolvers docker", server)

    def test_sync_skips_only_the_rebound_target(self):
        import sync

        result = {"errors": []}
        good = {"target_ip": "10.21.0.7", "target_port": 80, "enabled": True}
        bad = {"target_ip": "rebind.example", "target_port": 80, "enabled": True}

        def fake(host):
            if host == "rebind.example":
                raise targets.TargetError("blocked_target")
            return host

        with mock.patch.object(targets, "validate", side_effect=fake):
            safe = sync._targets_valid([good, bad], result)
        self.assertEqual(safe, [good])
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("rebind.example", result["errors"][0])


class ExternalDnsApiTests(fixtures.unittest.TestCase):
    setUp = fixtures.ManualServiceApiTests.setUp
    _login = fixtures.ManualServiceApiTests._login
    _csrf = fixtures.ManualServiceApiTests._csrf
    _post = fixtures.ManualServiceApiTests._post

    def _payload(self, **overrides):
        data = {"name": "Ext", "host": "app.example.com", "port": 8080, "protocol": "tcp"}
        data.update(overrides)
        return data

    def test_external_dns_requires_opt_in(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("203.0.113.10")
        ):
            response = self._post("/api/manual-services", self._payload())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "external_dns_opt_in")

    def test_external_dns_opt_in_is_stored(self):
        with mock.patch.object(
            targets.socket, "getaddrinfo", return_value=_resolve("203.0.113.10")
        ):
            response = self._post(
                "/api/manual-services", self._payload(allow_external=True)
            )
        self.assertEqual(response.status_code, 201, response.get_json())
        entry = next(
            item for item in state.load()["manual_services"] if item["host"] == "app.example.com"
        )
        self.assertTrue(entry["allow_external"])

    def test_docker_targets_do_not_need_the_flag(self):
        response = self._post(
            "/api/manual-services",
            self._payload(host="demo_web_1", name="Docker"),
        )
        self.assertEqual(response.status_code, 201, response.get_json())

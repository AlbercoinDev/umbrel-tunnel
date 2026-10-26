"""Unit tests for the Umbrel gateway.

Run from ``umbrel-tunnel/gateway``:

    PYTHONPATH=/tmp/opencode/pylibs python3 -m unittest discover -s tests -v

The tests use temporary directories and never touch the host WireGuard or
HAProxy configuration.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TMP = tempfile.mkdtemp(prefix="umbrel-tunnel-test-")
os.environ["UMBREL_TUNNEL_DATA"] = TMP
os.environ["UMBREL_APP_DATA"] = os.path.join(TMP, "app-data")
os.environ["APP_PASSWORD"] = "test-password"
os.environ["APP_VERSION"] = "test"
os.environ["UMBREL_TUNNEL_WG_CONF"] = os.path.join(TMP, "wg0.conf")
os.environ["UMBREL_TUNNEL_HAPROXY_CONF"] = os.path.join(TMP, "haproxy.cfg")
os.environ["UMBREL_TUNNEL_HAPROXY_PID"] = os.path.join(TMP, "haproxy.pid")
os.environ.pop("UMBREL_TUNNEL_DEV", None)

import app as gateway  # noqa: E402
import detect  # noqa: E402
import i18n  # noqa: E402
import state  # noqa: E402
import wireguard  # noqa: E402


VALID_KEY = "a" * 43 + "="
SERVER_KEY = "b" * 43 + "="


class I18nTests(unittest.TestCase):
    def test_catalogs_have_identical_keys(self):
        base = Path(i18n.I18N_DIR)
        es = json.loads((base / "es.json").read_text(encoding="utf-8"))
        en = json.loads((base / "en.json").read_text(encoding="utf-8"))
        self.assertEqual(set(es), set(en))
        self.assertGreater(len(es), 100)

    def test_default_is_spanish(self):
        request = SimpleNamespace(args={}, cookies={}, headers={})
        self.assertEqual(i18n.resolve(request), "es")

    def test_query_beats_cookie_and_header(self):
        request = SimpleNamespace(
            args={"lang": "en"},
            cookies={"ut_lang": "es"},
            headers={"Accept-Language": "es-ES,es;q=0.9"},
        )
        self.assertEqual(i18n.resolve(request), "en")

    def test_accept_language_uses_best_supported(self):
        request = SimpleNamespace(
            args={},
            cookies={},
            headers={"Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8,es;q=0.7"},
        )
        self.assertEqual(i18n.resolve(request), "en")

    def test_unsupported_language_falls_back_to_spanish(self):
        request = SimpleNamespace(args={"lang": "de"}, cookies={}, headers={})
        self.assertEqual(i18n.resolve(request), "es")


class WireGuardTests(unittest.TestCase):
    def test_build_config_is_structured(self):
        text = wireguard.build_config(
            VALID_KEY, "10.0.0.2", SERVER_KEY, "203.0.113.10:51820"
        )
        self.assertIn("PrivateKey = " + VALID_KEY, text)
        self.assertIn("Address = 10.0.0.2/24", text)
        self.assertIn("Endpoint = 203.0.113.10:51820", text)
        self.assertIn("AllowedIPs = 10.0.0.0/24", text)

    def test_build_config_rejects_client_outside_subnet(self):
        with self.assertRaises(wireguard.WireGuardError):
            wireguard.build_config(
                VALID_KEY, "10.9.9.9", SERVER_KEY, "203.0.113.10:51820"
            )

    def test_build_config_rejects_bad_endpoint(self):
        with self.assertRaises(wireguard.WireGuardError):
            wireguard.build_config(
                VALID_KEY, "10.0.0.2", SERVER_KEY, "not-an-endpoint"
            )

    def test_validate_config_rejects_hooks(self):
        malicious = (
            "[Interface]\n"
            f"PrivateKey = {VALID_KEY}\n"
            "Address = 10.0.0.2/24\n"
            "PostUp = touch /tmp/pwned\n"
        )
        with self.assertRaises(wireguard.WireGuardError):
            wireguard.validate_config(malicious)

    def test_validate_config_accepts_generated_config(self):
        text = wireguard.build_config(
            VALID_KEY, "10.0.0.2", SERVER_KEY, "203.0.113.10:51820"
        )
        wireguard.validate_config(text)

    def test_redacted_config_hides_private_key(self):
        text = wireguard.build_config(
            VALID_KEY, "10.0.0.2", SERVER_KEY, "203.0.113.10:51820"
        )
        wireguard.save_config(text)
        redacted = wireguard.redacted_config()
        self.assertNotIn(VALID_KEY, redacted)
        self.assertIn("PrivateKey = <redacted>", redacted)

    def test_overlap_detection(self):
        self.assertTrue(wireguard.overlaps_network("10.21.0.0/16", "10.21.0.0/24"))
        self.assertFalse(wireguard.overlaps_network("10.0.0.0/24", "10.21.0.0/16"))


class PairValidationTests(unittest.TestCase):
    def test_api_must_be_inside_tunnel_subnet(self):
        self.assertEqual(
            gateway.validate_api_url("http://10.0.0.1:8080", "10.0.0.0/24"),
            "http://10.0.0.1:8080",
        )
        for api in (
            "http://192.168.1.1:8080",
            "http://169.254.169.254/latest",
            "http://example.com:8080",
            "http://user:pass@10.0.0.1:8080",
        ):
            with self.assertRaises(ValueError, msg=api):
                gateway.validate_api_url(api, "10.0.0.0/24")

    def test_decode_pair_rejects_out_of_subnet_api(self):
        payload = {
            "v": 1,
            "api": "http://192.168.1.1:8080",
            "token": "x",
            "subnet": "10.0.0.0/24",
            "umbrel_ip": "10.0.0.2",
        }
        code = "ut1." + base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        with self.assertRaises(gateway.PairError) as ctx:
            gateway.decode_pair(code)
        self.assertEqual(ctx.exception.code, "pair_api")

    def test_decode_pair_rejects_non_object_payload(self):
        code = "ut1." + base64.urlsafe_b64encode(b"[1,2,3]").decode().rstrip("=")
        with self.assertRaises(gateway.PairError) as ctx:
            gateway.decode_pair(code)
        self.assertEqual(ctx.exception.code, "pair_invalid")


def pair_code(**overrides) -> str:
    payload = {
        "v": 1,
        "api": "http://10.0.0.1:8080",
        "token": "tok",
        "endpoint": "8.8.8.8:51820",
        "server_pubkey": SERVER_KEY,
        "umbrel_ip": "10.0.0.2",
        "subnet": "10.0.0.0/24",
        "mtu": 1420,
    }
    payload.update(overrides)
    return "ut1." + base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        state.CONFIG_FILE.unlink(missing_ok=True)
        gateway._login_attempts.clear()
        self.client = gateway.app.test_client()
        self._login()

    def _csrf(self):
        with self.client.session_transaction() as sess:
            return sess.get("csrf", "")

    def _login(self):
        self.client.get("/login")
        return self.client.post(
            "/login",
            data={"password": "test-password", "csrf_token": self._csrf()},
            follow_redirects=False,
        )

    def _post(self, path, payload):
        return self.client.post(
            path,
            json=payload,
            headers={"X-CSRF-Token": self._csrf()},
        )

    def _create_bootstrap(self, **overrides):
        body = {"vps_ip": "8.8.8.8"}
        body.update(overrides)
        with mock.patch.object(
            gateway.wireguard, "ensure_keypair", return_value=(VALID_KEY, SERVER_KEY)
        ):
            response = self._post("/api/bootstrap", body)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_bootstrap_is_initially_inactive(self):
        response = self.client.get("/api/bootstrap")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"active": False})

    def test_bootstrap_builds_quoted_install_command(self):
        data = self._create_bootstrap()
        self.assertTrue(data["active"])
        self.assertEqual(data["endpoint"], "8.8.8.8:51820")
        self.assertEqual(data["api"], "http://10.0.0.1:8080")
        self.assertEqual(data["public_key"], SERVER_KEY)
        self.assertNotIn("token", data)
        self.assertIn("--umbrel-pubkey", data["command"])
        self.assertIn("--binary-base", data["command"])
        self.assertIn("install.sh", data["command"])

        tokens = shlex.split(data["command"])
        self.assertEqual(tokens[tokens.index("--endpoint") + 1], "8.8.8.8")
        self.assertEqual(tokens[tokens.index("--subnet") + 1], "10.0.0.0/24")
        self.assertEqual(tokens[tokens.index("--umbrel-ip") + 1], "10.0.0.2")

    def test_install_command_quotes_untrusted_values(self):
        bootstrap = {
            "vps_ip": "8.8.8.8",
            "token": "a b'c",
            "public_key": SERVER_KEY,
            "subnet": "10.0.0.0/24",
            "server_ip": "10.0.0.1",
            "umbrel_ip": "10.0.0.2",
            "api_port": 8080,
            "wg_port": 51820,
            "mtu": 1420,
        }
        tokens = shlex.split(gateway.install_command(bootstrap))
        self.assertEqual(tokens[tokens.index("--token") + 1], "a b'c")

    def test_bootstrap_rejects_private_vps_ip(self):
        response = self._post("/api/bootstrap", {"vps_ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "vps_ip_not_public")

    def test_bootstrap_rejects_invalid_subnet(self):
        response = self._post(
            "/api/bootstrap", {"vps_ip": "8.8.8.8", "subnet": "10.0.0.0/31"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "pair_subnet")

    def test_bootstrap_reuses_token_for_same_vps(self):
        self._create_bootstrap()
        first = state.load()["bootstrap"]["token"]
        self._create_bootstrap()
        second = state.load()["bootstrap"]["token"]
        self.assertEqual(first, second)

    def test_pasted_installer_block_is_accepted(self):
        code = pair_code()
        block = (
            "--- umbrel-tunnel: emparejamiento ---\n"
            f"Código: {code}\n"
            "Pega este bloque en la app de Umbrel.\n"
            "---------------------------------\n"
        )
        payload = gateway.decode_pair(block)
        self.assertEqual(payload["token"], "tok")
        self.assertEqual(payload["api"], "http://10.0.0.1:8080")

    def test_pair_rejects_code_that_does_not_match_bootstrap(self):
        self._create_bootstrap()
        response = self._post("/api/pair", {"code": pair_code(token="other")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "pair_bootstrap_mismatch")
        self.assertTrue(state.load()["bootstrap"])

    def test_matching_bootstrap_pairs_and_clears_it(self):
        data = self._create_bootstrap()
        token = state.load()["bootstrap"]["token"]
        code = pair_code(
            token=token,
            endpoint=data["endpoint"],
            api=data["api"],
            umbrel_ip=data["umbrel_ip"],
            subnet=data["subnet"],
        )
        sync_result = {
            "ok": True,
            "created": 0,
            "updated": 0,
            "deleted": 0,
            "errors": [],
            "vps_status": None,
            "at": 1,
        }
        with (
            mock.patch.object(
                gateway.wireguard, "ensure_keypair", return_value=(VALID_KEY, SERVER_KEY)
            ),
            mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")),
            mock.patch.object(gateway, "ensure_peer"),
            mock.patch.object(gateway, "sync_now", return_value=sync_result),
        ):
            response = self._post("/api/pair", {"code": code})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        config = state.load()
        self.assertTrue(state.paired(config))
        self.assertEqual(config["bootstrap"], {})
        self.assertEqual(config["vps"]["token"], token)

    def test_pair_without_bootstrap_still_works(self):
        code = pair_code()
        sync_result = {
            "ok": True,
            "created": 0,
            "updated": 0,
            "deleted": 0,
            "errors": [],
            "vps_status": None,
            "at": 1,
        }
        with (
            mock.patch.object(
                gateway.wireguard, "ensure_keypair", return_value=(VALID_KEY, SERVER_KEY)
            ),
            mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")),
            mock.patch.object(gateway, "ensure_peer"),
            mock.patch.object(gateway, "sync_now", return_value=sync_result),
        ):
            response = self._post("/api/pair", {"code": code})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(state.paired(state.load()))

    def test_bootstrap_rejected_when_already_paired(self):
        self._create_bootstrap()
        token = state.load()["bootstrap"]["token"]
        code = pair_code(token=token)
        with (
            mock.patch.object(
                gateway.wireguard, "ensure_keypair", return_value=(VALID_KEY, SERVER_KEY)
            ),
            mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")),
            mock.patch.object(gateway, "ensure_peer"),
            mock.patch.object(
                gateway,
                "sync_now",
                return_value={
                    "ok": True,
                    "created": 0,
                    "updated": 0,
                    "deleted": 0,
                    "errors": [],
                    "vps_status": None,
                    "at": 1,
                },
            ),
        ):
            self._post("/api/pair", {"code": code})
        response = self._post("/api/bootstrap", {"vps_ip": "8.8.8.8"})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "already_paired")


class DetectTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="app-data-", dir=TMP))
        self._old = detect.APP_DATA
        detect.APP_DATA = self.root

    def tearDown(self):
        detect.APP_DATA = self._old

    def _write_app(self, app_id: str, manifest: str, compose: str, gateway_cfg: dict):
        app_dir = self.root / app_id
        app_dir.mkdir(parents=True)
        (app_dir / "umbrel-app.yml").write_text(manifest, encoding="utf-8")
        (app_dir / "docker-compose.yml").write_text(compose, encoding="utf-8")
        (app_dir / "app-gateway.json").write_text(
            json.dumps(gateway_cfg), encoding="utf-8"
        )

    def test_resolved_gateway_config_is_primary_source(self):
        self._write_app(
            "demo-app",
            "manifestVersion: 1.1\nid: demo-app\nname: Demo\nport: 8080\n",
            (
                "services:\n"
                "  app_proxy:\n"
                "    environment:\n"
                "      APP_HOST: demo-app_web_1\n"
                "      APP_PORT: 3000\n"
                "  web:\n"
                "    image: demo\n"
                "    ports:\n"
                "      - '9000:9000'\n"
            ),
            {"APP_HOST": "demo-app_web_1", "APP_PORT": 3000},
        )
        services = detect.detect_services()
        by_port = {svc["target_port"]: svc for svc in services}
        self.assertIn(3000, by_port)
        self.assertEqual(by_port[3000]["target_ip"], "demo-app_web_1")
        self.assertEqual(by_port[3000]["app"], "Demo")
        self.assertIn(9000, by_port)

    def test_localhost_targets_are_rejected(self):
        self.assertIsNone(
            detect._entry("x", "X", "web", "127.0.0.1", 8080)
        )
        self.assertIsNone(
            detect._entry("x", "X", "web", "localhost", 8080)
        )
        self.assertIsNotNone(
            detect._entry("x", "X", "web", "x_web_1", 8080)
        )

    def test_exports_is_never_executed(self):
        app_dir = self.root / "evil-app"
        app_dir.mkdir()
        marker = self.root / "executed"
        (app_dir / "exports.sh").write_text(
            f"touch {marker}\nAPP_PORT=1234\n", encoding="utf-8"
        )
        (app_dir / "umbrel-app.yml").write_text(
            "name: Evil\nport: 8080\n", encoding="utf-8"
        )
        (app_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        detect.detect_services()
        self.assertFalse(marker.exists())

    def test_system_services_carry_translation_key(self):
        old_host = detect._detect_host
        detect._detect_host = lambda: [
            detect._entry(
                "umbrel-os",
                "UmbrelOS",
                "ssh",
                "10.21.0.1",
                22,
                source="system",
                system=True,
                sensitive=True,
                name_key="system.ssh",
            )
        ]
        try:
            services = detect.detect_services()
        finally:
            detect._detect_host = old_host
        ssh = next(svc for svc in services if svc["service"] == "ssh")
        self.assertEqual(ssh["name_key"], "system.ssh")
        self.assertIn("system.ssh", i18n.catalog("en"))


class AuthTests(unittest.TestCase):
    def setUp(self):
        state.CONFIG_FILE.unlink(missing_ok=True)
        gateway._login_attempts.clear()
        self.client = gateway.app.test_client()

    def _csrf(self):
        with self.client.session_transaction() as sess:
            return sess.get("csrf", "")

    def _login(self):
        self.client.get("/login")
        return self.client.post(
            "/login",
            data={"password": "test-password", "csrf_token": self._csrf()},
            follow_redirects=False,
        )

    def test_health_is_public(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])

    def test_api_requires_login(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["code"], "unauthorized")

    def test_index_redirects_to_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_wrong_password_is_rejected(self):
        self.client.get("/login")
        response = self.client.post(
            "/login",
            data={"password": "nope", "csrf_token": self._csrf()},
        )
        self.assertEqual(response.status_code, 401)

    def test_login_requires_csrf(self):
        self.client.get("/login")
        response = self.client.post("/login", data={"password": "test-password"})
        self.assertEqual(response.status_code, 403)

    def test_login_and_csrf_protected_post(self):
        response = self._login()
        self.assertEqual(response.status_code, 302)
        status = self.client.get("/api/status")
        self.assertEqual(status.status_code, 200)

        denied = self.client.post("/api/sync")
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.get_json()["code"], "csrf")

        allowed = self.client.post(
            "/api/sync", headers={"X-CSRF-Token": self._csrf()}
        )
        self.assertEqual(allowed.status_code, 200)

    def test_index_is_csp_safe(self):
        self._login()
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="ut-config"', html)
        self.assertIn('type="application/json"', html)
        self.assertNotIn("window.UT", html)
        self.assertNotIn("<script>", html)
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)

    def test_index_contains_app_first_onboarding(self):
        self._login()
        html = self.client.get("/").get_data(as_text=True)
        for element_id in (
            "onboarding",
            "bootstrap-form",
            "bootstrap-pending",
            "bootstrap-command",
            "bootstrap-link-form",
            "pair-card",
        ):
            self.assertIn(f'id="{element_id}"', html)

    def test_unsafe_next_is_ignored(self):
        self.client.get("/login")
        response = self.client.post(
            "/login",
            data={
                "password": "test-password",
                "csrf_token": self._csrf(),
                "next": "//evil.example",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_logout_clears_session(self):
        self._login()
        response = self.client.post(
            "/logout", headers={"X-CSRF-Token": self._csrf()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/api/status").status_code, 401)


if __name__ == "__main__":
    unittest.main()

"""Sondas de salud: no bloquean el panel y no inventan estados."""

from unittest import mock

import test_gateway as fixtures
import app as gateway
import health
import state


def _exposure(**overrides):
    data = {
        "id": "e1",
        "name": "Demo",
        "target_ip": "10.21.0.7",
        "target_port": 8080,
        "protocol": "tcp",
        "access_mode": "direct",
        "enabled": True,
    }
    data.update(overrides)
    return data


class HealthProbeTests(fixtures.unittest.TestCase):
    def setUp(self):
        with health._LOCK:
            health._CACHE.clear()
        self.addCleanup(health.stop)
        with health._LOCK:
            health._CACHE.clear()

    def test_tcp_ok_records_latency(self):
        with mock.patch.object(
            health.socket, "create_connection", return_value=mock.MagicMock()
        ):
            result = health.check(_exposure())
        self.assertEqual(result["state"], "ok")
        self.assertIsNotNone(result["latency_ms"])

    def test_tcp_failure_is_reported(self):
        with mock.patch.object(
            health.socket, "create_connection", side_effect=ConnectionRefusedError("refused")
        ):
            result = health.check(_exposure())
        self.assertEqual(result["state"], "fail")
        self.assertIn("refused", result["detail"])

    def test_disabled_is_paused(self):
        self.assertEqual(health.check(_exposure(enabled=False))["state"], "paused")

    def test_sync_error_fails_without_probing(self):
        with mock.patch.object(
            health.socket, "create_connection", side_effect=AssertionError("no probe")
        ):
            result = health.check(_exposure(sync_error="VPS 409"))
        self.assertEqual(result["state"], "fail")

    def test_udp_is_unknown(self):
        self.assertEqual(health.check(_exposure(protocol="udp"))["state"], "unknown")

    def test_http_probe_does_not_fail_an_open_tcp_port(self):
        with mock.patch.object(
            health.socket, "create_connection", return_value=mock.MagicMock()
        ), mock.patch.object(health, "_http", return_value=(False, "not http")):
            result = health.check(_exposure(access_mode="https"))
        self.assertEqual(result["state"], "ok")
        self.assertIn("not http", result["detail"])

    def test_run_once_caches_results_and_summary(self):
        state.save({"exposures": [_exposure()]})
        self.addCleanup(state.CONFIG_FILE.unlink, missing_ok=True)
        self.addCleanup(state.BACKUP_FILE.unlink, missing_ok=True)
        with mock.patch.object(
            health, "check", return_value={"state": "ok", "detail": "", "latency_ms": 1, "checked_at": 1}
        ):
            health.run_once()
        self.assertEqual(health.snapshot()["e1"]["state"], "ok")
        summary = health.summary({"exposures": [_exposure()]})
        self.assertEqual((summary["ok"], summary["total"]), (1, 1))

    def test_summary_is_unknown_without_data(self):
        summary = health.summary({"exposures": [_exposure()]})
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["ok"], 0)

class HealthWidgetTests(fixtures.unittest.TestCase):
    setUp = fixtures.ManualServiceApiTests.setUp
    _login = fixtures.ManualServiceApiTests._login
    _csrf = fixtures.ManualServiceApiTests._csrf

    def test_panel_status_does_not_probe(self):
        with mock.patch.object(
            health.socket, "create_connection", side_effect=AssertionError("network in request")
        ):
            response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("health", data)
        self.assertIn("health_probe", data)

    def test_widget_shows_dashes_without_health_data(self):
        with health._LOCK:
            health._CACHE.clear()
        response = self.client.get("/api/widget", environ_base={"REMOTE_ADDR": "172.17.0.1"})
        self.assertEqual(response.status_code, 200)
        services = response.get_json()["items"][1]
        self.assertIn(services["text"], {"—", "0/0"})

    def test_widget_counts_only_verified_ok(self):
        with mock.patch.object(
            health,
            "summary",
            return_value={"total": 3, "ok": 2, "fail": 1, "unknown": 0, "checked_at": 1, "enabled": True},
        ), mock.patch.object(health, "snapshot", return_value={}):
            response = self.client.get("/api/widget", environ_base={"REMOTE_ADDR": "172.17.0.1"})
        data = response.get_json()
        self.assertEqual(data["items"][1]["text"], "2/3")
        self.assertIn("1", data["items"][1]["subtext"])

    def test_widget_shows_handshake_and_domain(self):
        status = {
            "running": True,
            "connected": True,
            "peers": [{"latest_handshake": int(__import__("time").time()) - 300}],
        }
        summary = {"total": 3, "ok": 3, "fail": 0, "unknown": 0, "checked_at": 1, "enabled": True}
        state.save({
            "vps": {"api": "http://10.0.0.1:8080", "token": "secret-token"},
            "settings": {"base_domain": "example.com"},
            "exposures": [],
        })
        self.addCleanup(state.CONFIG_FILE.unlink, missing_ok=True)
        self.addCleanup(state.BACKUP_FILE.unlink, missing_ok=True)
        with mock.patch.object(health, "summary", return_value=summary), \
                mock.patch.object(gateway.wireguard, "status", return_value=status):
            data = self.client.get("/api/widget", environ_base={"REMOTE_ADDR": "172.17.0.1"}).get_json()
        self.assertIn("5m", data["items"][0]["subtext"])
        self.assertEqual(data["items"][1]["text"], "3/3")
        self.assertEqual(data["items"][2]["text"], "example.com")

    def test_widget_localizes_with_accept_language(self):
        status = {"running": True, "connected": False, "peers": []}
        with mock.patch.object(gateway.wireguard, "status", return_value=status):
            english = self.client.get(
                "/api/widget?lang=en", environ_base={"REMOTE_ADDR": "172.17.0.1"}
            ).get_json()
            spanish = self.client.get(
                "/api/widget?lang=es", environ_base={"REMOTE_ADDR": "172.17.0.1"}
            ).get_json()
        self.assertEqual(english["items"][0]["text"], "Not connected")
        self.assertEqual(spanish["items"][0]["text"], "Sin conexión")

    def test_health_widget_reports_progress(self):
        summary = {"total": 4, "ok": 3, "fail": 1, "unknown": 0, "checked_at": 1, "enabled": True}
        with mock.patch.object(health, "summary", return_value=summary), \
                mock.patch.object(gateway.wireguard, "status", return_value={"running": True, "peers": []}):
            response = self.client.get(
                "/api/widget/health", environ_base={"REMOTE_ADDR": "172.17.0.1"}
            )
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["type"], "text-with-progress")
        self.assertEqual(data["text"], "3/4")
        self.assertAlmostEqual(data["progress"], 0.75, places=2)
        self.assertEqual(data["progressLabel"], "75%")
        self.assertEqual(data["refresh"], "30s")

    def test_widgets_are_public_without_a_session(self):
        anon = gateway.app.test_client()
        for path in ("/api/widget", "/api/widget/health"):
            response = anon.get(path, environ_base={"REMOTE_ADDR": "172.17.0.1"})
            self.assertEqual(response.status_code, 200, path)

    def test_widgets_reject_tunnel_requests(self):
        for path in ("/api/widget", "/api/widget/health"):
            response = self.client.get(path, environ_base={"REMOTE_ADDR": "10.0.0.1"})
            self.assertEqual(response.status_code, 403, path)

    def test_widgets_do_not_leak_secrets(self):
        status = {"running": True, "connected": True, "peers": [{"latest_handshake": 1}]}
        for path in ("/api/widget", "/api/widget/health"):
            with mock.patch.object(gateway.wireguard, "status", return_value=status):
                body = self.client.get(path, environ_base={"REMOTE_ADDR": "172.17.0.1"}).get_data(as_text=True)
            self.assertNotIn("token", body.lower())
            self.assertNotIn("private", body.lower())
            self.assertNotIn("secret-token", body)

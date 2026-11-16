"""Sondas de salud: no bloquean el panel y no inventan estados."""

from unittest import mock

import test_gateway as fixtures
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
        ):
            response = self.client.get("/api/widget", environ_base={"REMOTE_ADDR": "172.17.0.1"})
        self.assertEqual(response.get_json()["items"][1]["text"], "2/3")

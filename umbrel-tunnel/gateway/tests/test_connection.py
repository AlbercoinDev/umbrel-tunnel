"""Connection lifecycle tests model API loss when the tunnel identity changes."""
from unittest import mock

import test_gateway as fixtures
import app as gateway
import state
from vps import VPSError


class LifecycleTests(fixtures.unittest.TestCase):
    setUp = fixtures.ManualServiceApiTests.setUp
    _csrf = fixtures.ManualServiceApiTests._csrf
    _login = fixtures.ManualServiceApiTests._login
    _post = fixtures.ManualServiceApiTests._post
    _open_manual = fixtures.ManualServiceApiTests._open_manual

    def test_unpair_cleans_publications_before_revoking_tunnel(self):
        self._open_manual(public_port=9000)
        events = []

        class TunnelVPS(fixtures.FakeVPS):
            def delete_forward(self, forward_id):
                events.append("forward")
                super().delete_forward(forward_id)

            def delete_peer(self, peer_id):
                events.append("peer")
                if self.forwards:
                    raise AssertionError("peer removed before its forwards")

        with mock.patch.object(gateway, "VPSClient", TunnelVPS), mock.patch.object(gateway.sync, "VPSClient", TunnelVPS), mock.patch.object(gateway.wireguard, "remove"), mock.patch.object(gateway.sync.udp, "stop"):
            response = self._post("/api/unpair", {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(events, ["forward", "peer"])
        self.assertFalse(state.load()["vps"])

    def test_unpair_failure_preserves_credentials_and_tunnel(self):
        self._open_manual(public_port=9000)
        fixtures.FakeVPS.fail = "API unreachable"
        with mock.patch.object(gateway.wireguard, "remove") as remove:
            response = self._post("/api/unpair", {})
        self.assertEqual(response.status_code, 502)
        self.assertTrue(state.load()["vps"]["token"])
        remove.assert_not_called()

    def _rotation_config(self):
        config = state.load()
        config["vps"].update(endpoint="203.0.113.10:51820", server_pubkey="b" * 43 + "=")
        state.save(config)

    def test_force_unpair_is_explicit_and_reports_incomplete_remote_cleanup(self):
        self._open_manual(public_port=9000)
        fixtures.FakeVPS.fail = "API unreachable"
        with mock.patch.object(gateway.wireguard, "remove"), mock.patch.object(gateway.sync.udp, "stop"):
            response = self._post("/api/unpair", {"force": True})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["remote_cleaned"])
        self.assertFalse(state.load()["vps"])
        self.assertEqual(len(fixtures.FakeVPS.forwards), 1)

    def test_rotation_prepares_over_old_tunnel_and_confirms_over_new(self):
        self._rotation_config()
        events = []

        class RotationVPS(fixtures.FakeVPS):
            def prepare_rotation(self, peer_id, public_key):
                self_test.assertNotIn("apply", events)
                events.append("prepare")
                return {"rotation_id": "rotation"}

            def confirm_rotation(self, peer_id, rotation_id):
                self_test.assertIn("apply", events)
                events.append("confirm")
                return {"ok": True}

        self_test = self
        def apply():
            events.append("apply")
            return True, "ok"

        with mock.patch.object(gateway, "VPSClient", RotationVPS), mock.patch.object(gateway.wireguard, "config_text", return_value="old"), mock.patch.object(gateway.wireguard, "private_key", return_value="a" * 43 + "="), mock.patch.object(gateway.wireguard, "generate_keypair", return_value=("c" * 43 + "=", "d" * 43 + "=")), mock.patch.object(gateway.wireguard, "save_config"), mock.patch.object(gateway.wireguard, "save_private_key"), mock.patch.object(gateway.wireguard, "apply_saved", side_effect=apply):
            response = self._post("/api/wireguard/rotate", {})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(events, ["prepare", "apply", "confirm"])

    def test_old_vps_rejects_rotation_before_local_key_changes(self):
        self._rotation_config()
        with mock.patch.object(gateway.wireguard, "generate_keypair", return_value=("c" * 43 + "=", "d" * 43 + "=")), mock.patch.object(gateway.wireguard, "config_text", return_value=""), mock.patch.object(gateway.wireguard, "private_key", return_value=""), mock.patch.object(gateway.wireguard, "save_private_key") as save, mock.patch.object(fixtures.FakeVPS, "prepare_rotation", create=True, side_effect=VPSError("upgrade VPS", status=404)):
            response = self._post("/api/wireguard/rotate", {})
        self.assertEqual(response.status_code, 502)
        save.assert_not_called()

    def test_failed_confirmation_restores_local_key_and_config(self):
        self._rotation_config()
        with mock.patch.object(fixtures.FakeVPS, "prepare_rotation", create=True, return_value={"rotation_id": "r"}), mock.patch.object(fixtures.FakeVPS, "confirm_rotation", create=True, side_effect=VPSError("no new tunnel")), mock.patch.object(gateway.time, "monotonic", side_effect=[0, 50]), mock.patch.object(gateway.wireguard, "generate_keypair", return_value=("c" * 43 + "=", "d" * 43 + "=")), mock.patch.object(gateway.wireguard, "config_text", return_value="old config"), mock.patch.object(gateway.wireguard, "private_key", return_value="a" * 43 + "="), mock.patch.object(gateway.wireguard, "save_private_key") as save_key, mock.patch.object(gateway.wireguard, "save_config") as save_config, mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")) as apply:
            response = self._post("/api/wireguard/rotate", {})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(save_key.call_args_list[-1], mock.call("a" * 43 + "="))
        self.assertEqual(save_config.call_args_list[-1], mock.call("old config"))
        self.assertEqual(apply.call_count, 2)

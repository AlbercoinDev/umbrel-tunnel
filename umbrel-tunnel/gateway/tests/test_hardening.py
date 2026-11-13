"""1.4.2 hardening: tunnel-side panel access, state integrity, locking, release pins."""
from pathlib import Path
from unittest import mock

import test_gateway as fixtures
import app as gateway
import state
import wireguard
from vps import VPSError


class Base(fixtures.unittest.TestCase):
    setUp = fixtures.ManualServiceApiTests.setUp
    _csrf = fixtures.ManualServiceApiTests._csrf
    _login = fixtures.ManualServiceApiTests._login
    _post = fixtures.ManualServiceApiTests._post
    _open_manual = fixtures.ManualServiceApiTests._open_manual


class TunnelAccessTests(Base):
    def test_panel_rejects_requests_arriving_through_the_tunnel(self):
        for remote in ("10.0.0.1", "10.0.0.7"):
            response = self.client.get("/api/status", environ_base={"REMOTE_ADDR": remote})
            self.assertEqual(response.status_code, 403, remote)
            self.assertEqual(response.get_json()["code"], "tunnel_forbidden")
        login = self.client.get("/login", environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.assertEqual(login.status_code, 403)

    def test_panel_still_serves_docker_network_and_healthcheck(self):
        ok = self.client.get("/api/status", environ_base={"REMOTE_ADDR": "10.21.0.5"})
        self.assertEqual(ok.status_code, 200)
        health = self.client.get("/api/health", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(health.status_code, 200)

    def test_subnet_from_live_wireguard_config_is_also_blocked(self):
        with mock.patch.object(gateway.wireguard, "subnet", return_value="10.9.0.0/24"):
            self.assertTrue(gateway.from_tunnel("10.9.0.1"))
        self.assertFalse(gateway.from_tunnel("not-an-ip"))


class StateIntegrityTests(fixtures.unittest.TestCase):
    def setUp(self):
        state.CONFIG_FILE.unlink(missing_ok=True)
        state.BACKUP_FILE.unlink(missing_ok=True)
        self.addCleanup(state.CONFIG_FILE.unlink, missing_ok=True)
        self.addCleanup(state.BACKUP_FILE.unlink, missing_ok=True)

    def test_missing_file_is_a_fresh_install(self):
        self.assertEqual(state.load()["vps"], {})

    def test_corrupt_file_falls_back_to_last_good_copy(self):
        state.save({"vps": {"api": "http://10.0.0.1:8080", "token": "t"}})
        state.CONFIG_FILE.write_text("{truncated", encoding="utf-8")
        self.assertEqual(state.load()["vps"]["token"], "t")

    def test_corrupt_file_without_backup_is_never_replaced_by_defaults(self):
        state.CONFIG_FILE.write_text("{truncated", encoding="utf-8")
        with self.assertRaises(state.StateError):
            state.load()
        self.assertEqual(state.CONFIG_FILE.read_text(encoding="utf-8"), "{truncated")


class LockingTests(Base):
    def test_delete_holds_sync_lock_and_not_state_lock_during_vps_call(self):
        self._open_manual(public_port=9000)
        observed = {}

        class ObservingVPS(fixtures.FakeVPS):
            def delete_forward(self, forward_id):
                observed["sync_lock"] = gateway._sync_lock._is_owned()
                observed["state_lock"] = state.LOCK._is_owned()
                super().delete_forward(forward_id)

        exposure_id = state.load()["exposures"][0]["id"]
        with mock.patch.object(gateway, "VPSClient", ObservingVPS):
            response = self.client.delete(
                f"/api/exposures/{exposure_id}", headers={"X-CSRF-Token": self._csrf()}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(observed, {"sync_lock": True, "state_lock": False})
        self.assertEqual(state.load()["exposures"], [])


class RotationRecoveryTests(Base):
    OLD = "a" * 43 + "="

    def setUp(self):
        super().setUp()
        self.addCleanup(wireguard.clear_pending_rotation)
        wireguard.save_pending_rotation(
            {"peer_id": "p1", "rotation_id": "r1", "old_private": self.OLD, "old_config": "old config"}
        )

    def test_no_pending_rotation_is_a_noop(self):
        wireguard.clear_pending_rotation()
        self.assertEqual(gateway.recover_rotation(state.load()), "none")

    def test_rotation_still_held_by_vps_is_confirmed(self):
        with mock.patch.object(fixtures.FakeVPS, "confirm_rotation", create=True, return_value={"ok": True}), \
                mock.patch.object(gateway, "_restore_wireguard") as restore:
            self.assertEqual(gateway.recover_rotation(state.load()), "confirmed")
        restore.assert_not_called()
        self.assertEqual(wireguard.pending_rotation(), {})

    def test_expired_rotation_restores_previous_key_and_config(self):
        expired = VPSError("VPS HTTP 409: rotación no encontrada o caducada", status=409)
        with mock.patch.object(fixtures.FakeVPS, "confirm_rotation", create=True, side_effect=expired), \
                mock.patch.object(gateway.wireguard, "save_private_key") as save_key, \
                mock.patch.object(gateway.wireguard, "save_config") as save_config, \
                mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")):
            self.assertEqual(gateway.recover_rotation(state.load()), "restored")
        save_key.assert_called_once_with(self.OLD)
        save_config.assert_called_once_with("old config")
        self.assertEqual(wireguard.pending_rotation(), {})

    def test_successful_rotation_leaves_no_pending_marker(self):
        wireguard.clear_pending_rotation()
        config = state.load()
        config["vps"].update(endpoint="203.0.113.10:51820", server_pubkey="b" * 43 + "=")
        state.save(config)
        with mock.patch.object(fixtures.FakeVPS, "prepare_rotation", create=True, return_value={"rotation_id": "r"}), \
                mock.patch.object(fixtures.FakeVPS, "confirm_rotation", create=True, return_value={"ok": True}), \
                mock.patch.object(gateway.wireguard, "generate_keypair", return_value=("c" * 43 + "=", "d" * 43 + "=")), \
                mock.patch.object(gateway.wireguard, "config_text", return_value="old"), \
                mock.patch.object(gateway.wireguard, "private_key", return_value=self.OLD), \
                mock.patch.object(gateway.wireguard, "save_config"), \
                mock.patch.object(gateway.wireguard, "save_private_key"), \
                mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")):
            response = self._post("/api/wireguard/rotate", {})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(wireguard.pending_rotation(), {})


class ReleasePinTests(fixtures.unittest.TestCase):
    def test_release_version_matches_vps_and_pins_installer_urls(self):
        root = Path(__file__).resolve().parents[3]
        version = (root / "vps/VERSION").read_text().strip()
        self.assertEqual(gateway.RELEASE_VERSION, version)
        self.assertIn(f"/v{version}/vps/install.sh", gateway.DEFAULT_INSTALL_URL)
        self.assertTrue(gateway.DEFAULT_BINARY_BASE.endswith(f"/releases/download/v{version}"))
        self.assertNotIn("/main/", gateway.DEFAULT_INSTALL_URL)

    def test_installer_verifies_downloaded_binary(self):
        script = (Path(__file__).resolve().parents[3] / "vps/install.sh").read_text()
        self.assertIn('verify_download "$tmp" "$BINARY"', script)
        self.assertIn('"$url.sha256"', script)

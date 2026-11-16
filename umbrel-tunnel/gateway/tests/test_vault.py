"""Cifrado en reposo de config.json y de las claves de WireGuard."""

from pathlib import Path

import test_gateway as fixtures  # fija UMBREL_TUNNEL_DATA antes de importar
import state
import vault
import wireguard

VALID_KEY = "a" * 43 + "="
SERVER_KEY = "b" * 43 + "="

CONFIG_TEXT = (
    "[Interface]\n"
    f"PrivateKey = {VALID_KEY}\n"
    "Address = 10.0.0.2/24\n"
    "MTU = 1420\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {SERVER_KEY}\n"
    "Endpoint = 203.0.113.10:51820\n"
    "AllowedIPs = 10.0.0.0/24\n"
    "PersistentKeepalive = 25\n"
)


class VaultTests(fixtures.unittest.TestCase):
    def setUp(self):
        state.CONFIG_FILE.unlink(missing_ok=True)
        state.BACKUP_FILE.unlink(missing_ok=True)
        self.addCleanup(state.CONFIG_FILE.unlink, missing_ok=True)
        self.addCleanup(state.BACKUP_FILE.unlink, missing_ok=True)

    def test_roundtrip_hides_the_plaintext(self):
        text = '{"vps": {"token": "super-secret"}}'
        sealed = vault.encrypt(text)
        self.assertTrue(vault.is_envelope(sealed))
        self.assertNotIn("super-secret", sealed)
        self.assertEqual(vault.decrypt(sealed), text)

    def test_state_is_written_encrypted(self):
        state.save({"vps": {"api": "http://10.0.0.1:8080", "token": "tok-123"}})
        raw = state.CONFIG_FILE.read_text(encoding="utf-8")
        self.assertTrue(vault.is_envelope(raw))
        self.assertNotIn("tok-123", raw)
        self.assertNotIn("10.0.0.1", raw)
        self.assertEqual(state.load()["vps"]["token"], "tok-123")

    def test_plaintext_state_is_migrated_in_place(self):
        state.CONFIG_FILE.write_text('{"vps": {"token": "tok-legacy"}}', encoding="utf-8")
        self.assertTrue(state.migrate_encryption())
        self.assertTrue(vault.is_envelope(state.CONFIG_FILE.read_text(encoding="utf-8")))
        self.assertEqual(state.load()["vps"]["token"], "tok-legacy")
        self.assertFalse(state.migrate_encryption())

    def test_wrong_key_fails_closed(self):
        sealed = vault.encrypt("secreto")
        original_key = vault.KEY_FILE.read_text(encoding="ascii")
        original = vault._KEY
        try:
            vault._KEY = None
            vault.KEY_FILE.write_text("11" * 32 + "\n", encoding="ascii")
            with self.assertRaises(vault.SecretsError):
                vault.decrypt(sealed)
        finally:
            vault.KEY_FILE.write_text(original_key, encoding="ascii")
            vault._KEY = original

    def test_corrupt_key_file_fails_closed_without_overwriting(self):
        original_key = vault.KEY_FILE.read_text(encoding="ascii")
        original = vault._KEY
        try:
            vault._KEY = None
            vault.KEY_FILE.write_text("no-es-hex\n", encoding="ascii")
            with self.assertRaises(vault.SecretsError):
                vault.key()
            self.assertEqual(vault.KEY_FILE.read_text(encoding="ascii"), "no-es-hex\n")
        finally:
            vault.KEY_FILE.write_text(original_key, encoding="ascii")
            vault._KEY = original

    def test_wireguard_files_are_encrypted_and_readable(self):
        wireguard.save_config(CONFIG_TEXT)
        self.assertTrue(vault.is_envelope(wireguard.DATA_CONF.read_text(encoding="utf-8")))
        self.assertEqual(wireguard.config_text().rstrip(), CONFIG_TEXT.rstrip())

        wireguard.save_private_key(VALID_KEY)
        self.assertTrue(vault.is_envelope(wireguard.DATA_KEY.read_text(encoding="utf-8")))
        self.assertEqual(wireguard.private_key(), VALID_KEY)

    def test_pending_rotation_is_encrypted(self):
        wireguard.save_pending_rotation(
            {"peer_id": "p1", "rotation_id": "r1", "old_private": VALID_KEY}
        )
        raw = wireguard.PENDING_ROTATION.read_text(encoding="utf-8")
        self.assertTrue(vault.is_envelope(raw))
        self.assertNotIn(VALID_KEY, raw)
        self.assertEqual(wireguard.pending_rotation()["old_private"], VALID_KEY)
        wireguard.clear_pending_rotation()

    def test_legacy_wireguard_files_migrate(self):
        wireguard.DATA_WG_DIR.mkdir(parents=True, exist_ok=True)
        wireguard.DATA_CONF.write_text(CONFIG_TEXT, encoding="utf-8")
        wireguard.DATA_KEY.write_text(VALID_KEY + "\n", encoding="ascii")
        migrated = wireguard.migrate_encryption()
        self.assertIn("wg0.conf", migrated)
        self.assertIn("private.key", migrated)
        self.assertTrue(vault.is_envelope(wireguard.DATA_CONF.read_text(encoding="utf-8")))
        self.assertEqual(wireguard.private_key(), VALID_KEY)

"""Cadena de auditoría: append, redacción y detección de manipulación."""

import json
from unittest import mock

# test_gateway sets UMBREL_TUNNEL_DATA before importing the app and modules.
from test_gateway import unittest

import audit
import state


class AuditTests(unittest.TestCase):
    def setUp(self):
        audit.AUDIT_FILE.unlink(missing_ok=True)
        audit.ROTATED_FILE.unlink(missing_ok=True)
        self.addCleanup(audit.AUDIT_FILE.unlink, missing_ok=True)
        self.addCleanup(audit.ROTATED_FILE.unlink, missing_ok=True)

    def test_empty_log_is_valid(self):
        self.assertEqual(audit.verify(), {"ok": True, "entries": 0, "reason": "empty"})

    def test_entries_are_chained_and_redacted(self):
        audit.log("test_event", token="super-secret", host="10.21.0.5")
        audit.log("second_event", password="another-secret")

        text = audit.AUDIT_FILE.read_text(encoding="utf-8")
        self.assertNotIn("super-secret", text)
        self.assertNotIn("another-secret", text)
        self.assertIn("10.21.0.5", text)
        self.assertEqual(audit.verify(), {"ok": True, "entries": 2, "reason": "ok"})

    def test_tampering_breaks_the_chain(self):
        audit.log("first", host="10.21.0.5")
        audit.log("second", host="10.21.0.6")
        lines = audit.AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["host"] = "tampered"
        lines[0] = json.dumps(entry)
        audit.AUDIT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = audit.verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["entries"], 0)
        self.assertTrue(result["reason"].startswith("hash:"))

    def test_log_never_breaks_the_caller(self):
        # Un directorio de datos no escribible no debe lanzar desde la petición.
        with mock.patch.object(audit, "AUDIT_FILE", state.DATA_DIR / "missing" / "audit.log"):
            audit.log("ignored")

"""1.5.0 shared VPS: several Umbrels on one VPS, each limited to its own domain."""
import shlex
from unittest import mock

import test_gateway as fixtures
import app as gateway
import state

SYNC_OK = {"ok": True, "created": 0, "updated": 0, "deleted": 0, "errors": [], "vps_status": None, "at": 1}


class SharedBootstrapTests(fixtures.unittest.TestCase):
    # Borrow the helpers only, so BootstrapTests' own tests do not run twice.
    setUp = fixtures.BootstrapTests.setUp
    _csrf = fixtures.BootstrapTests._csrf
    _login = fixtures.BootstrapTests._login
    _post = fixtures.BootstrapTests._post
    _create_bootstrap = fixtures.BootstrapTests._create_bootstrap

    def _pair(self, code):
        with (
            mock.patch.object(gateway.wireguard, "ensure_keypair", return_value=(fixtures.VALID_KEY, fixtures.SERVER_KEY)),
            mock.patch.object(gateway.wireguard, "apply_saved", return_value=(True, "ok")),
            mock.patch.object(gateway, "ensure_peer"),
            mock.patch.object(gateway, "sync_now", return_value=SYNC_OK),
        ):
            return self._post("/api/pair", {"code": code})

    def test_shared_domain_generates_peer_add_instead_of_installer(self):
        data = self._create_bootstrap(shared_domain="Oficina.Example.com")
        self.assertEqual(data["shared_domain"], "oficina.example.com")
        self.assertEqual(data["umbrel_ip"], "")
        tokens = shlex.split(data["command"])
        self.assertEqual(tokens[:4], ["sudo", "umbrel-tunnel", "peer", "add"])
        self.assertEqual(tokens[tokens.index("--domain") + 1], "oficina.example.com")
        self.assertEqual(tokens[tokens.index("--pubkey") + 1], fixtures.SERVER_KEY)
        self.assertEqual(tokens[tokens.index("--token") + 1], state.load()["bootstrap"]["token"])
        self.assertNotIn("install.sh", data["command"])

    def test_invalid_shared_domain_is_rejected(self):
        response = self._post("/api/bootstrap", {"vps_ip": "8.8.8.8", "shared_domain": "no domain"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "invalid_shared_domain")

    def test_vps_assigned_address_pairs_and_domain_becomes_base(self):
        data = self._create_bootstrap(shared_domain="oficina.example.com")
        token = state.load()["bootstrap"]["token"]
        wrong = fixtures.pair_code(token=token, endpoint=data["endpoint"], umbrel_ip="10.0.0.3", domain="otra.example.com")
        self.assertEqual(self._pair(wrong).get_json()["code"], "pair_bootstrap_mismatch")

        code = fixtures.pair_code(token=token, endpoint=data["endpoint"], umbrel_ip="10.0.0.3", domain="oficina.example.com")
        response = self._pair(code)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        config = state.load()
        self.assertEqual(config["vps"]["umbrel_ip"], "10.0.0.3")
        self.assertEqual(config["vps"]["domain"], "oficina.example.com")
        self.assertEqual(config["settings"]["base_domain"], "oficina.example.com")

    def test_shared_node_cannot_leave_its_domain(self):
        self._pair(fixtures.pair_code(umbrel_ip="10.0.0.3", domain="oficina.example.com"))
        ok = self._post("/api/settings", {"base_domain": "apps.oficina.example.com"})
        self.assertEqual(ok.status_code, 200, ok.get_data(as_text=True))
        bad = self._post("/api/settings", {"base_domain": "casa.example.com"})
        self.assertEqual(bad.status_code, 400)
        config = state.load()
        exposure = {"id": "e1", "protocol": "tcp"}
        with self.assertRaises(ValueError):
            gateway.configure_publication_access(config, exposure, {"access_mode": "https", "domain": "mempool.casa.example.com"})
        with self.assertRaises(ValueError):
            gateway.configure_publication_access(config, exposure, {"access_mode": "https", "domain": "mempool.xoficina.example.com"})

    def test_pair_code_domain_is_validated(self):
        with self.assertRaises(gateway.PairError) as ctx:
            gateway.decode_pair(fixtures.pair_code(domain="Not A Domain"))
        self.assertEqual(ctx.exception.code, "pair_domain")
        self.assertEqual(gateway.decode_pair(fixtures.pair_code())["domain"], "")

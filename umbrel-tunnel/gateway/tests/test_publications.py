import unittest
from unittest import mock

import test_gateway as fixtures

gateway = fixtures.gateway
state = fixtures.state
sync = fixtures.sync


class PublicationTests(unittest.TestCase):
    _login = fixtures.ManualServiceApiTests._login
    _csrf = fixtures.ManualServiceApiTests._csrf
    _post = fixtures.ManualServiceApiTests._post
    _patch = fixtures.ManualServiceApiTests._patch
    _open_manual = fixtures.ManualServiceApiTests._open_manual

    def setUp(self):
        fixtures.ManualServiceApiTests.setUp(self)
        patcher = mock.patch.object(sync.udp, "apply")
        self.udp_apply = patcher.start()
        self.addCleanup(patcher.stop)

    def test_udp_can_be_published_and_share_tcp_port(self):
        tcp = self._open_manual(protocol="tcp", public_port=9000).get_json()
        udp = self._open_manual(protocol="udp", public_port=9000).get_json()
        self.assertEqual(tcp["exposure"]["public_port"], 9000)
        self.assertEqual(udp["exposure"]["public_port"], 9000)
        self.assertEqual(udp["exposure"]["protocol"], "udp")
        self.assertTrue(udp["ok"])
        rule = state.load()["exposures"][-1]
        self.assertEqual(rule["access_mode"], "direct")
        self.assertEqual(rule["tls"]["mode"], "none")
        paused = self._patch('/api/exposures/' + rule['id'], {"enabled": False})
        self.assertEqual(paused.status_code, 200)
        resumed = self._patch('/api/exposures/' + rule['id'], {"enabled": True})
        self.assertTrue(resumed.get_json()["ok"])

    def test_udp_wireguard_port_is_reserved(self):
        response = self._open_manual(protocol="udp", public_port=51820)
        self.assertEqual(response.status_code, 400)

    def test_cli_change_is_not_silently_overwritten_and_can_be_adopted(self):
        result = self._open_manual(public_port=9000).get_json()
        rule = result["exposure"]
        fixtures.FakeVPS.forwards[0]["public_port"] = 9001
        gateway.sync_now()
        self.assertEqual(fixtures.FakeVPS.forwards[0]["public_port"], 9001)
        self.assertTrue(state.load()["exposures"][0]["remote_conflict"])
        response = self._post('/api/exposures/' + rule['id'] + '/resolve', {"action": "adopt"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(state.load()["exposures"][0]["public_port"], 9001)

    def test_cli_change_can_be_restored(self):
        result = self._open_manual(public_port=9000).get_json()
        fixtures.FakeVPS.forwards[0]["public_port"] = 9001
        gateway.sync_now()
        response = self._post('/api/exposures/' + result['exposure']['id'] + '/resolve', {"action": "restore"})
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(fixtures.FakeVPS.forwards[0]["public_port"], 9000)

    def test_vps_owned_rules_are_not_removed(self):
        fixtures.FakeVPS.forwards.append({"id": "manual", "name": "umbrel:operator-rule", "managed_by": "vps"})
        gateway.sync_now()
        self.assertEqual(len(fixtures.FakeVPS.forwards), 1)

    def test_tls_can_be_enabled_later_without_an_extra_cleartext_forward(self):
        result = self._open_manual(port=50001, public_port=50001).get_json()
        rule = result["exposure"]
        response = self._patch('/api/exposures/' + rule['id'], {
            "access_mode": "tls", "domain": "electrs.example.org",
            "public_port": 50002, "accept_acme_terms": True,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(len(fixtures.FakeVPS.forwards), 1)
        remote = fixtures.FakeVPS.forwards[0]
        self.assertEqual(remote["access_mode"], "tls")
        self.assertEqual(remote["public_port"], 50002)
        self.assertEqual(remote["domain"], "electrs.example.org")
        self.assertEqual(state.load()["exposures"][0]["target_port"], 50001)
        self.assertTrue(gateway.sync_now()["ok"])

    def test_multiple_https_domains_share_443_and_require_terms(self):
        first = self._open_manual(port=8081, public_port=8081).get_json()["exposure"]
        second = self._open_manual(port=8082, public_port=8082).get_json()["exposure"]
        for rule, domain in [(first, "web.example.org"), (second, "bin.example.org")]:
            payload = {"access_mode": "https", "domain": domain, "accept_acme_terms": True}
            result = self._patch('/api/exposures/' + rule['id'], payload)
            self.assertTrue(result.get_json()["ok"], result.get_json())
        self.assertEqual([f["public_port"] for f in fixtures.FakeVPS.forwards], [443, 443])
        response = self._patch('/api/exposures/' + first['id'], {"access_mode": "https", "domain": "new.example.org"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(state.load()["exposures"][0]["domains"], ["web.example.org"])

    def test_tls_port_conflict_is_not_reassigned(self):
        rule = self._open_manual(port=50001, public_port=50001).get_json()["exposure"]
        fixtures.FakeVPS.conflict_ports.add(50002)
        response = self._patch('/api/exposures/' + rule['id'], {"access_mode": "tls", "domain": "electrs.example.org", "public_port": 50002, "accept_acme_terms": True})
        self.assertFalse(response.get_json()["ok"])
        self.assertEqual(state.load()["exposures"][0]["public_port"], 50002)

    def test_new_manual_service_can_start_secure_without_direct_publication(self):
        response = self._open_manual(port=50001, open=False)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(fixtures.FakeVPS.forwards, [])
        manual = state.load()["manual_services"][0]
        response = self._post('/api/exposures', {
            "service_id": f"manual:{manual['id']}:50001:tcp", "access_mode": "tls",
            "domain": "electrs.example.org", "public_port": 50002,
            "accept_acme_terms": True,
        })
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(len(fixtures.FakeVPS.forwards), 1)
        self.assertEqual(fixtures.FakeVPS.forwards[0]["access_mode"], "tls")
        self.assertEqual(fixtures.FakeVPS.forwards[0]["public_port"], 50002)

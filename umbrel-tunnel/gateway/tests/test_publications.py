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

    def test_http_is_always_published_on_80_and_https_on_443(self):
        self._post('/api/settings', {"base_domain": "umbrel.example.org"})
        self._open_manual(port=3006, open=False)
        manual = state.load()["manual_services"][0]

        plain = self._new_publication(
            manual, access_mode="http", subdomain="web", public_port=3006
        )
        self.assertEqual(plain.status_code, 201, plain.get_data(as_text=True))
        self.assertEqual(plain.get_json()["exposure"]["public_port"], 80)
        self.assertEqual(fixtures.FakeVPS.forwards[0]["public_port"], 80)
        self.assertEqual(fixtures.FakeVPS.forwards[0]["domain"], "web.umbrel.example.org")

        secure = self._new_publication(
            manual, access_mode="https", subdomain="secure",
            public_port=3006, accept_acme_terms=True,
        )
        self.assertEqual(secure.status_code, 201, secure.get_data(as_text=True))
        self.assertEqual(secure.get_json()["exposure"]["public_port"], 443)
        self.assertEqual(
            {f["public_port"] for f in fixtures.FakeVPS.forwards}, {80, 443}
        )

        fixed = self._patch(
            '/api/exposures/' + plain.get_json()["exposure"]["id"],
            {"public_port": 8080},
        )
        self.assertEqual(fixed.status_code, 400)
        self.assertEqual(fixed.get_json()["code"], "web_port_fixed")
        self.assertEqual(state.load()["exposures"][0]["public_port"], 80)

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

    def _new_publication(self, manual, **values):
        return self._post('/api/exposures', {"service_id": f"manual:{manual['id']}:{manual['port']}:{manual['protocol']}", "new_publication": True, **values})

    def test_same_service_has_plain_and_tls_same_domain_and_independent_controls(self):
        self.assertEqual(self._post('/api/settings', {"base_domain": "umbrel.example.org"}).status_code, 200)
        self._open_manual(port=50001, open=False)
        manual = state.load()["manual_services"][0]
        plain = self._new_publication(manual, access_mode="direct", subdomain="electrs", public_port=50001).get_json()
        secure = self._new_publication(manual, access_mode="tls", subdomain="electrs", public_port=50002, accept_acme_terms=True).get_json()
        self.assertTrue(plain["ok"], plain)
        self.assertTrue(secure["ok"], secure)
        self.assertNotEqual(plain["exposure"]["id"], secure["exposure"]["id"])
        exposures = state.load()["exposures"]
        self.assertEqual(len(exposures), 2)
        self.assertEqual({e["target_port"] for e in exposures}, {50001})
        self.assertEqual({tuple(e["domains"]) for e in exposures}, {("electrs.umbrel.example.org",)})
        self.assertEqual({f["public_port"] for f in fixtures.FakeVPS.forwards}, {50001,50002})
        self.assertTrue(gateway.sync_now()["ok"])
        paused = self._patch('/api/exposures/' + secure['exposure']['id'], {"enabled": False})
        self.assertTrue(paused.get_json()["ok"])
        self.assertEqual([f["public_port"] for f in fixtures.FakeVPS.forwards], [50001])
        response = self.client.delete('/api/exposures/' + secure['exposure']['id'], headers={"X-CSRF-Token":self._csrf()})
        self.assertEqual(response.status_code,200)
        self.assertEqual(len(state.load()["exposures"]),1)
        self.assertEqual(fixtures.FakeVPS.forwards[0]["domain"], "electrs.umbrel.example.org")

    def test_domain_change_does_not_rewrite_publications_and_settings_do_not_publish(self):
        self._post('/api/settings', {"base_domain":"umbrel.example.org"})
        self.assertEqual(fixtures.FakeVPS.forwards,[])
        self._open_manual(port=50001,open=False)
        manual=state.load()["manual_services"][0]
        self._new_publication(manual,access_mode="direct",subdomain="electrs",public_port=50001)
        old=list(fixtures.FakeVPS.forwards)
        self._post('/api/settings', {"base_domain":"other.example.org"})
        self.assertEqual(state.load()["exposures"][0]["domains"],["electrs.umbrel.example.org"])
        self.assertEqual(fixtures.FakeVPS.forwards,old)
        self.assertEqual(self._post('/api/settings', {"base_domain":"https://invalid/*"}).status_code,400)
        self.assertEqual(state.load()["settings"]["base_domain"],"other.example.org")

    def test_domains_without_certificates_and_tcp_port_collision(self):
        self._post('/api/settings', {"base_domain":"umbrel.example.org"})
        self._open_manual(port=50001,open=False)
        manual=state.load()["manual_services"][0]
        first=self._new_publication(manual,access_mode="direct",subdomain="electrs",public_port=50001)
        self.assertTrue(first.get_json()["ok"])
        second=self._new_publication(manual,access_mode="direct",subdomain="different",public_port=50001)
        self.assertEqual(second.status_code,400)
        self.assertEqual(len(state.load()["exposures"]),1)
        self.assertEqual(fixtures.FakeVPS.forwards[0]["public_port"],50001)

    def test_http_without_tls_can_share_port_by_domain(self):
        self._post('/api/settings', {"base_domain":"umbrel.example.org"})
        self._open_manual(port=8080,open=False)
        manual=state.load()["manual_services"][0]
        for sub in ["one","two"]:
            response=self._new_publication(manual,access_mode="http",subdomain=sub,public_port=80)
            self.assertTrue(response.get_json()["ok"],response.get_json())
        self.assertEqual(len(fixtures.FakeVPS.forwards),2)
        self.assertTrue(all(e["tls"]["mode"]=="none" for e in state.load()["exposures"]))

    def test_same_domain_multiple_tls_ports_and_plain_domain_conflict_keeps_port(self):
        self._post('/api/settings', {"base_domain":"umbrel.example.org"})
        self._open_manual(port=50001,open=False)
        manual=state.load()["manual_services"][0]
        for port in [50002,50003]:
            response=self._new_publication(manual,access_mode="tls",subdomain="electrs",public_port=port,accept_acme_terms=True)
            self.assertTrue(response.get_json()["ok"],response.get_json())
        self.assertEqual(len(fixtures.FakeVPS.forwards),2)
        self.assertEqual(len({f["domain"] for f in fixtures.FakeVPS.forwards}),1)

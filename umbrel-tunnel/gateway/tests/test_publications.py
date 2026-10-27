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

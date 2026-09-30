"""Run actual firewall shell logic against explicit CLI/ubus/fw4 boundaries."""
import unittest

from test_backend_firewall_support import DEVICE, NETWORK_ID, FirewallHarness


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.harness = FirewallHarness()
        self.addCleanup(self.harness.temp.cleanup)

    def test_missing_options_publish_no_permissions(self):
        result, payload = self.harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload, {'name': 'zerotier', 'data': {'firewall': []}})

    def test_network_flags_generate_input_two_way_forward_and_any_family_nat(self):
        result, payload = self.harness.run(values={
            'network1:fw_allow_input': '1', 'network1:fw_allow_forward': '1',
            'network1:fw_allow_masq': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = payload['data']['firewall']
        self.assertEqual(len(rules), 4)
        self.assertEqual(rules[0], {'type': 'rule', 'src': '*', 'device': DEVICE,
                                   'direction': 'in', 'proto': 'all', 'target': 'ACCEPT'})
        self.assertEqual([rule['direction'] for rule in rules[1:3]], ['in', 'out'])
        self.assertTrue(all(rule['dest'] == '*' for rule in rules[1:3]))
        self.assertEqual(rules[3], {'type': 'nat', 'device': DEVICE, 'family': 'any',
                                   'proto': 'all', 'target': 'MASQUERADE'})

    def test_global_rule_opens_only_actual_udp_ports(self):
        result, payload = self.harness.run(values={'global:fw_allow_input': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = payload['data']['firewall']
        self.assertEqual([rule['dest_port'] for rule in rules], ['9993', '20000'])
        self.assertTrue(all(rule['proto'] == 'udp' and rule['src'] == '*' for rule in rules))

    def test_disabled_network_and_removed_device_grant_nothing(self):
        for values, command in [({'network1:enabled': '0'}, 'zt_fw_refresh'),
                                ({}, f'zt_fw_refresh {DEVICE}')]:
            with self.subTest(command=command):
                settings = {'network1:fw_allow_input': '1', **values}
                result, payload = self.harness.run(values=settings, command=command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(payload['data']['firewall'], [])

    def test_other_service_data_survives_and_old_rules_are_replaced(self):
        metadata = {'mdns': {'_http._tcp': ['a', 2, True, None]},
                    'other-key': {'precision': 1.2345678912}}
        service = {'zerotier': {'instances': {'one': {'running': True}},
                               'data': {**metadata, 'firewall': [{'old': True}]}}}
        result, payload = self.harness.run(service=service)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload['data'], {**metadata, 'firewall': []})

    def test_absent_service_does_not_publish_or_reload(self):
        result, payload = self.harness.run(service={})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(payload)
        self.assertNotIn('fw4:', (self.harness.base / 'calls').read_text())

    def test_cli_startup_wait_stops_when_service_disappears(self):
        result, payload = self.harness.run(failure='stopped')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(payload)

    def test_cli_readiness_retries_then_uses_real_snapshot(self):
        result, payload = self.harness.run(failure='delay')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload['data']['firewall'], [])

    def test_nonrunning_services_do_not_wait_or_publish(self):
        for instances in [{}, {'one': {'running': False}}]:
            with self.subTest(instances=instances):
                result, payload = self.harness.run(service={'zerotier': {'instances': instances}})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(payload)
                self.assertNotIn('cli:', (self.harness.base / 'calls').read_text())

    def test_permanently_unavailable_cli_fails_readiness(self):
        result, payload = self.harness.run(failure='unavailable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('readiness', result.stderr)
        self.assertIsNone(payload)

    def test_invalid_reloaded_configuration_fails_without_publishing(self):
        for failure in ['invalid_reload_enabled', 'invalid_reload_network']:
            with self.subTest(failure=failure):
                result, payload = self.harness.run(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)

    def test_invalid_interface_is_rejected_without_publishing(self):
        result, payload = self.harness.run(networks=[{
            'id': NETWORK_ID, 'portDeviceName': 'ztbad;accept', 'status': 'OK'}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(payload)

    def test_duplicate_network_mapping_is_rejected(self):
        network = {'id': NETWORK_ID, 'portDeviceName': DEVICE, 'status': 'OK'}
        result, payload = self.harness.run(networks=[network, network])
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(payload)

    def test_invalid_port_is_rejected(self):
        result, payload = self.harness.run(values={'global:fw_allow_input': '1'},
            info={'config': {'settings': {'primaryPort': 0, 'secondaryPort': 'invalid'}}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(payload)

    def test_publish_and_reload_errors_propagate(self):
        for failure in ['listnetworks', 'ucode', 'set_data', 'fw4']:
            with self.subTest(failure=failure):
                result, _ = self.harness.run(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('zerotier-f50:', result.stderr)

    def test_clear_preserves_other_data_and_does_not_query_daemon(self):
        result, payload = self.harness.run(command='zt_fw_clear', service={
            'zerotier': {'data': {'marker': 'keep', 'firewall': [{'old': True}]}}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload['data'], {'marker': 'keep', 'firewall': []})
        self.assertNotIn('cli:', (self.harness.base / 'calls').read_text())


if __name__ == '__main__':
    unittest.main()

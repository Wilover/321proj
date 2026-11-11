"""Response boundary checks: identity is not permission or causal attribution."""
import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from ai_rdr_actions import Actions
from ai_rdr_policy import response_decision
from ai_rdr_response import wazuh
from freeze_verify_manager import Workflow
from test_response import FakeRuntime


class ResponsePolicyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.r = FakeRuntime(Path(self.folder.name))
        self.r.config.update(agent_id='001', automatic_actions=[])

    def data(self, **changes):
        return {'case_id': 'POLICY', 'pid': 42, 'start_ticks': 100, 'boot_id': 'boot',
                'risk_score': .75, 'response_mode': 'automatic', **changes}

    def evidence(self, **changes):
        return {'type': 'decoy_write', 'event_id': 'AUDIT-1', 'pid': 42,
                'start_ticks': 100, 'boot_id': 'boot', **changes}

    def send(self, action='freeze', data=None, command='add'):
        data = self.data() if data is None else data
        payload = {'command': command, 'parameters': {'alert': {
            'id': 'A-' + action + ('-delete' if command == 'delete' else ''), 'agent': {'id': '001'},
            'timestamp': '2026-11-11T09:00:00Z', 'data': data}}}
        # Each vector has its own temporary store; deletes keep the incident ID.
        wazuh(self.r, action, io.StringIO(json.dumps(payload) + '\n' + (
            '{"command":"continue"}\n' if command == 'add' else '')), io.StringIO())
        return self.r.store.timeline(data['case_id'])

    def decision(self, events):
        return next(e['details'] for e in events if e['event_type'] == 'response.policy_evaluated')

    def assert_no_effects(self):
        self.assertEqual(self.r.signals, [])
        self.assertFalse((self.r.store.load_state() or {}).get('resources'))
        self.assertFalse((self.r.store.load_state() or {}).get('cases'))

    def test_identified_process_and_high_score_do_not_grant_permission(self):
        decision = self.decision(self.send(data=self.data(risk_score=.99)))
        self.assertTrue(decision['target_identified'])
        self.assertFalse(decision['automatic_response_allowed'])
        self.assertFalse(decision['execution_allowed'])
        self.assert_no_effects()

    def test_config_permission_still_requires_explicit_automatic_mode(self):
        self.r.config['automatic_actions'] = ['freeze']
        data = self.data()
        del data['response_mode']
        decision = self.decision(self.send(data=data))
        self.assertEqual(decision['reason'], 'explicit_automatic_mode_required')
        self.assert_no_effects()

    def test_configured_action_and_matching_target_can_execute(self):
        self.r.config['automatic_actions'] = ['freeze']
        decision = self.decision(self.send())
        self.assertTrue(decision['target_identified'])
        self.assertTrue(decision['automatic_response_allowed'])
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])

    def test_permission_without_current_process_identity_cannot_execute(self):
        self.r.config['automatic_actions'] = ['freeze']
        decision = self.decision(self.send(data=self.data(start_ticks=99)))
        self.assertFalse(decision['target_identified'])
        self.assertTrue(decision['automatic_response_allowed'])
        self.assertFalse(decision['execution_allowed'])
        self.assert_no_effects()

    def test_nested_m2_alert_only_cannot_be_overridden(self):
        self.r.config['automatic_actions'] = ['freeze']
        decision = self.decision(self.send(data=self.data(ml={
            'ransomware_probability': .98, 'threshold': .13, 'response_mode': 'alert_only'})))
        self.assertEqual(decision['reason'], 'ml_alert_only')
        self.assert_no_effects()

    def test_actual_m2_shape_does_not_supply_process_identity(self):
        data = {'case_id': 'POLICY', 'ransomware_probability': .73, 'threshold': .13,
                'prediction': 'ransomware', 'alert': True, 'response_mode': 'alert_only',
                'model_name': 'random_forest', 'target_identified': True,
                'automatic_response_allowed': True, 'analyst_approved': True}
        decision = self.decision(self.send(data=data))
        self.assertFalse(decision['target_identified'])
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

        recorded = self.r.store.get_case('POLICY')['alerts'][0]
        self.assertEqual(recorded['ransomware_probability'], .73)
        self.assertEqual(recorded['threshold'], .13)
        self.assertEqual(recorded['model_name'], 'random_forest')

    def test_forged_permission_and_approval_fields_are_not_authority(self):
        decision = self.decision(self.send(data=self.data(
            target_identified=True, automatic_response_allowed=True, analyst_approved=True)))
        self.assertFalse(decision['automatic_response_allowed'])
        self.assertEqual(decision['permission_source'], 'none')
        self.assert_no_effects()

    def test_attributed_decoy_remains_independent_of_ml_mode(self):
        with patch.object(Actions, 'firewall'):
            decision = self.decision(self.send('kill', self.data(
                response_mode='alert_only', evidence=self.evidence())))
        self.assertTrue(decision['target_identified'])
        self.assertTrue(decision['automatic_response_allowed'])
        self.assertEqual(decision['permission_source'], 'attributed_decoy')
        self.assertIn((42, signal.SIGKILL), self.r.signals)

    def test_independent_decoy_policy_can_be_disabled(self):
        self.r.config['attributed_decoy_actions'] = []
        decision = self.decision(self.send(data=self.data(evidence=self.evidence())))
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_possible_host_time_link_does_not_become_decoy_attribution(self):
        evidence = {'type': 'decoy_write', 'event_id': 'M3-1',
                    'host': '001', 'correlation': 'possible_link'}
        decision = self.decision(self.send(data=self.data(evidence=evidence)))
        self.assertTrue(decision['target_identified'])  # M2 target, not M3's actor.
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_evidence_from_another_process_does_not_authorise_target(self):
        decision = self.decision(self.send(data=self.data(evidence=self.evidence(pid=43))))
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_boolean_process_identity_is_not_accepted_as_integer(self):
        decision = self.decision(self.send(data=self.data(start_ticks=True)))
        self.assertFalse(decision['target_identified'])
        self.assert_no_effects()

    def test_host_identification_does_not_authorise_isolation(self):
        with patch.object(Actions, 'firewall') as firewall:
            decision = self.decision(self.send('isolate'))
        firewall.assert_not_called()
        self.assertTrue(decision['target_identified'])
        self.assertEqual(decision['target_kind'], 'host')
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_ip_identification_does_not_authorise_blocking(self):
        with patch.object(Actions, 'firewall') as firewall:
            decision = self.decision(self.send('block', self.data(src_ip='192.0.2.99')))
        firewall.assert_not_called()
        self.assertTrue(decision['target_identified'])
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_stale_decoy_identity_cannot_authorise_standalone_isolation(self):
        data = self.data(start_ticks=99, evidence=self.evidence(start_ticks=99))
        with patch.object(Actions, 'firewall') as firewall:
            decision = self.decision(self.send('isolate', data))
        firewall.assert_not_called()
        self.assertTrue(decision['target_identified'])  # Endpoint exists; actor is stale.
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_account_identification_does_not_authorise_disabling(self):
        with patch.object(Actions, 'account_snapshot', return_value={'uid': 1001}), \
                patch.object(Actions, 'account') as account:
            decision = self.decision(self.send('disable', self.data(username='test-user')))
        account.assert_not_called()
        self.assertTrue(decision['target_identified'])
        self.assertFalse(decision['automatic_response_allowed'])
        self.assert_no_effects()

    def test_non_string_ip_is_not_an_identified_ip_target(self):
        self.r.config['automatic_actions'] = ['block']
        decision = self.decision(self.send('block', self.data(src_ip=True)))
        self.assertFalse(decision['target_identified'])
        self.assert_no_effects()

    def test_approval_requirement_also_gates_standalone_isolation(self):
        self.r.config.update(automatic_actions=['isolate'], require_approval=True)
        with patch.object(Actions, 'firewall') as firewall:
            decision = self.decision(self.send('isolate'))
        firewall.assert_not_called()
        self.assertEqual(decision['reason'], 'analyst_approval_required')
        self.assert_no_effects()

    def test_frozen_identity_is_rechecked_before_host_isolation(self):
        state = {'resources': {}, 'cases': {}}
        workflow = Workflow(self.r)
        workflow.freeze(state, 'POLICY', 42, 100, 'boot', None, self.evidence())
        self.r.processes[42]['start_ticks'] = 200
        with patch.object(Actions, 'firewall') as firewall:
            workflow.tick(state)
        firewall.assert_not_called()
        self.assertEqual(state['cases']['POLICY']['status'], 'REVIEW')
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])

    def test_recovery_does_not_bypass_revoked_decoy_permission(self):
        state = {'resources': {}, 'cases': {}}
        workflow = Workflow(self.r)
        record = workflow.freeze(state, 'POLICY', 42, 100, 'boot', None, self.evidence())
        record['status'] = 'CONTAINING'
        self.r.config['attributed_decoy_actions'] = []
        with patch.object(Actions, 'firewall') as firewall:
            workflow.tick(state)
        firewall.assert_not_called()
        self.assertEqual(record['status'], 'REVIEW')
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)

    def test_permission_to_freeze_does_not_grant_permission_to_kill(self):
        self.r.config['attributed_decoy_actions'] = ['freeze']
        state = {'resources': {}, 'cases': {}}
        workflow = Workflow(self.r)
        record = workflow.freeze(state, 'POLICY', 42, 100, 'boot', None, self.evidence())
        with patch.object(Actions, 'firewall') as firewall:
            workflow.tick(state)
        firewall.assert_not_called()
        self.assertEqual(record['status'], 'REVIEW')
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])

    def test_undo_remains_available_after_automatic_permission_is_removed(self):
        self.r.config['automatic_actions'] = ['isolate']
        with patch.object(Actions, 'firewall') as firewall:
            self.send('isolate')
            self.r.config['automatic_actions'] = []
            data = self.data()
            del data['response_mode']
            self.send('isolate', data, command='delete')
        self.assertEqual(firewall.call_count, 2)
        self.assertEqual(self.r.store.load_state()['resources'], {})

    def test_analyst_permission_is_not_misreported_as_automatic(self):
        decision = response_decision('kill', self.data(), {}, target_identified=True,
                                     analyst_approved=True)
        self.assertFalse(decision['automatic_response_allowed'])
        self.assertTrue(decision['execution_allowed'])
        self.assertEqual(decision['permission_source'], 'analyst')

    def test_direct_workflow_does_not_bypass_endpoint_policy(self):
        state = {'resources': {}, 'cases': {}}
        with self.assertRaises(PermissionError):
            Workflow(self.r).freeze(state, 'POLICY', 42, 100, 'boot', .75, response_mode='automatic')
        self.assertEqual(state, {'resources': {}, 'cases': {}})
        self.assert_no_effects()


if __name__ == '__main__':
    unittest.main()

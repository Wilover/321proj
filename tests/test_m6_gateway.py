"""M6 authenticated integration checks; process/firewall effects are simulated."""
from copy import deepcopy
from contextlib import contextmanager
import datetime as dt
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_rdr_actions import Actions
from ai_rdr_m6 import (GatewayError, M5Client, M6Gateway, SSHTransport, canonical,
                       signed, verify_signature)
from ai_rdr_risk import RiskMatrix
from freeze_verify_manager import Workflow
from test_response import FakeRuntime


KEY = b'unit-test-key-not-a-real-credential-32'
IDENTITY = {'pid': 42, 'start_ticks': 100, 'boot_id': 'boot'}


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.r = FakeRuntime(Path(self.folder.name))
        self.r.config.update(agent_id='001', automatic_actions=[],
                             m6_gateway={'enabled': True, 'issuer': 'm6-backend'})
        self.gateway = M6Gateway(self.r, KEY)
        self.r.store.create_case(case_id='C1', title='Integration case', actor=self.r.actor)
        self.requests = []
        self.client = self.make_client()

    def make_client(self, role='responder', kind='user', transport=None):
        def local(message):
            packet = json.loads(message)
            self.requests.append(deepcopy(packet))
            return canonical(self.gateway.handle(packet))
        return M5Client(transport or local, KEY, '001', {'type': kind, 'id': 'm6:rost', 'roles': [role]})

    def params(self, action, **changes):
        return {'reason': 'Controlled integration test',
                'idempotency_key': 'key-' + str(len(self.requests)),
                'expected_sequence': self.r.store.get_case('C1')['last_sequence'], **changes}

    def act(self, action, **changes):
        params = self.params(action, **changes)
        return self.client.request_action('C1', action, **params)

    def freeze(self):
        result = self.act('freeze', target=dict(IDENTITY))
        self.assertEqual(result['status'], 'completed')
        return result['result']['operation_id']

    def test_structured_case_risk_and_cursor_reads(self):
        self.assertEqual(self.client.list_cases()['items'][0]['case_id'], 'C1')
        risk = RiskMatrix().evaluate({'case_id': 'C1', 'agent_id': '001', **IDENTITY,
                                     'evidence': {'type': 'decoy_write', 'event_id': 'E1', **IDENTITY}})
        self.r.store.record_risk_decision(risk, actor=self.r.actor)
        projection = self.client.get_case('C1')
        self.assertEqual(projection['latest_risk_decision']['risk_level'], 'high')
        self.assertEqual(projection['process_operations'], [])
        first = self.client.timeline('C1', limit=1)
        second = self.client.timeline('C1', after=first['next_after'])
        self.assertTrue(second['items'])
        self.assertGreater(second['items'][0]['case_sequence'], first['next_after'])
        self.assertEqual(len(self.client.risk_decisions('C1')['items']), 1)

    def test_manual_freeze_does_not_require_or_enable_automatic_containment(self):
        operation = self.freeze()
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])
        state = self.r.store.load_state()
        record = state['cases'][operation]
        self.assertTrue(record['manual_review'])
        self.assertIsNot(record.get('analyst_approved'), True)
        record['evidence'] = {'type': 'decoy_write', 'event_id': 'E1', **IDENTITY}
        record['deadline'] = 0
        with patch.object(Actions, 'firewall') as firewall:
            Workflow(self.r).tick(state)
        firewall.assert_not_called()
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])

    def test_verify_is_read_only_and_does_not_grant_kill_approval(self):
        operation = self.freeze()
        result = self.act('verify', operation_id=operation)
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['result']['identity_valid'])
        self.assertTrue(result['result']['all_stopped'])
        self.assertFalse(result['result']['analyst_approved'])
        self.assertEqual(result['result']['malicious_verdict'], 'not_determined_by_identity_check')
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])

    def test_kill_only_never_isolates(self):
        operation = self.freeze()
        self.r.config['require_approval'] = True
        with patch.object(Actions, 'firewall') as firewall:
            result = self.act('kill', operation_id=operation)
        firewall.assert_not_called()
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['result']['isolation_requested'])
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP), (42, signal.SIGKILL)])

    def test_isolate_only_never_kills_and_thaw_does_not_undo_network(self):
        operation = self.freeze()
        with patch.object(Actions, 'firewall'):
            result = self.act('isolate', operation_id=operation)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['result']['process_terminated'])
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])
        thaw = self.act('thaw', operation_id=operation)
        self.assertEqual(thaw['status'], 'completed')
        self.assertIn('isolate:host', self.r.store.load_state()['resources'])
        with patch.object(Actions, 'firewall'):
            undo = self.act('undo', resource_key='isolate:host')
        self.assertTrue(undo['result']['restriction_removed'])
        self.assertEqual(self.r.store.load_state()['resources'], {})

    def test_combined_containment_is_explicit(self):
        operation = self.freeze()
        with patch.object(Actions, 'firewall') as firewall:
            result = self.act('approve_containment', operation_id=operation)
        self.assertTrue(firewall.called)
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['result']['isolation_requested'])
        self.assertIn((42, signal.SIGKILL), self.r.signals)

    def test_analyst_identity_request_and_executor_are_preserved(self):
        self.freeze()
        events = self.r.store.timeline('C1')
        request = next(e for e in events if e['event_type'] == 'analyst.requested')
        related = [e for e in events if e['request_id'] == request['request_id']]
        self.assertTrue(related)
        self.assertTrue(all(e['actor']['id'] == 'm6:rost' for e in related))
        self.assertEqual(request['details']['executor']['id'], 'm5-gateway:001')
        self.assertEqual(self.r.actor['type'], 'service')
        self.assertIsNone(self.r.request_id)

    def test_idempotent_retry_returns_same_verified_result_without_repeating_effect(self):
        params = self.params('freeze', target=dict(IDENTITY))
        first = self.client.request_action('C1', 'freeze', **params)
        second = self.client.request_action('C1', 'freeze', **params)
        self.assertEqual(first['request_id'], second['request_id'])
        self.assertEqual(second['status'], 'completed')
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])
        changed = params | {'reason': 'Different action body'}
        with self.assertRaises(GatewayError) as caught:
            self.client.request_action('C1', 'freeze', **changed)
        self.assertEqual(caught.exception.code, 'conflict')

    def test_interrupted_completion_is_uncertain_and_not_blindly_replayed(self):
        params = self.params('freeze', target=dict(IDENTITY))
        original = self.r.store.append_event
        def fail_completion(case_id, event_type, **kwargs):
            if event_type == 'analyst.completed':
                raise sqlite3.OperationalError('Injected completion write failure')
            return original(case_id, event_type, **kwargs)
        with patch.object(self.r.store, 'append_event', side_effect=fail_completion):
            with self.assertRaises(GatewayError):
                self.client.request_action('C1', 'freeze', **params)
        retry = self.client.request_action('C1', 'freeze', **params)
        self.assertEqual(retry['status'], 'uncertain')
        self.assertFalse(retry['completion_verified'])
        self.assertTrue(retry['may_have_effects'])
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])
        self.assertEqual(self.client.get_action(retry['request_id'])['status'], 'uncertain')

    def test_journal_failure_prevents_os_effects(self):
        with patch.object(self.r.store, 'begin_analyst_request', side_effect=sqlite3.OperationalError('full')):
            with self.assertRaises(GatewayError):
                self.act('freeze', target=dict(IDENTITY))
        self.assertEqual(self.r.signals, [])

    def test_expiry_is_rechecked_after_waiting_for_the_executor_lock(self):
        original = self.r.transaction
        @contextmanager
        def delayed_lock():
            with original() as state:
                self.gateway.clock = lambda: dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=3)
                yield state
        with patch.object(self.r, 'transaction', delayed_lock):
            with self.assertRaises(GatewayError) as caught:
                self.act('freeze', target=dict(IDENTITY))
        self.assertEqual(caught.exception.code, 'expired')
        self.assertEqual(self.r.signals, [])

    def test_refreeze_after_thaw_creates_a_new_operation(self):
        first = self.freeze()
        self.act('thaw', operation_id=first)
        second = self.freeze()
        self.assertNotEqual(first, second)
        self.assertEqual([sig for _, sig in self.r.signals], [signal.SIGSTOP, signal.SIGCONT, signal.SIGSTOP])

    def test_thaw_reports_preserved_preexisting_stops(self):
        self.r.processes[42]['state'] = 'T'
        operation = self.freeze()
        result = self.act('thaw', operation_id=operation)
        self.assertEqual(result['result']['preserved_stops'], [42])
        self.assertEqual(self.r.signals, [])

    def test_invalid_signature_does_not_create_endpoint_state(self):
        self.client.list_cases()
        packet = self.requests[-1]
        with tempfile.TemporaryDirectory() as folder:
            runtime = FakeRuntime(Path(folder))
            runtime.config.update(agent_id='001', m6_gateway={'enabled': True})
            gateway = M6Gateway(runtime, KEY)
            response = gateway.handle(signed(packet, b'wrong-signing-key-for-tests-123456'))
            self.assertFalse(response['ok'])
            self.assertEqual(response['error']['code'], 'unauthenticated')
            self.assertFalse((Path(folder) / 'aicm.sqlite3').exists())

    def test_viewer_and_service_principals_cannot_execute_manual_actions(self):
        for role, kind in (('viewer', 'user'), ('responder', 'service')):
            with self.subTest(role=role, kind=kind), self.assertRaises(GatewayError) as caught:
                self.make_client(role, kind).request_action('C1', 'freeze', **self.params('freeze', target=dict(IDENTITY)))
            self.assertEqual(caught.exception.code, 'forbidden')
        self.assertEqual(self.r.signals, [])
        self.assertTrue(self.r.store.timeline(None))  # Authenticated denial is audited.

    def test_analyst_role_can_freeze_but_cannot_kill(self):
        self.client = self.make_client('analyst')
        operation = self.freeze()
        with self.assertRaises(GatewayError) as caught:
            self.act('kill', operation_id=operation)
        self.assertEqual(caught.exception.code, 'forbidden')
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)

    def test_endpoint_allowlist_can_deny_even_a_responder(self):
        self.r.config['m6_gateway']['allowed_actions'] = ['verify']
        with self.assertRaises(GatewayError) as caught:
            self.act('freeze', target=dict(IDENTITY))
        self.assertEqual(caught.exception.code, 'forbidden')
        self.assertEqual(self.r.signals, [])

    def test_stale_view_and_forged_approval_fields_are_rejected(self):
        for params in (self.params('freeze', target=dict(IDENTITY), expected_sequence=0),
                       self.params('freeze', target=dict(IDENTITY), analyst_approved=True)):
            with self.subTest(params=params), self.assertRaises(GatewayError):
                self.client.request_action('C1', 'freeze', **params)
        self.assertEqual(self.r.signals, [])

    def test_stale_identity_or_protected_process_cannot_be_frozen(self):
        stale = self.act('freeze', target=IDENTITY | {'start_ticks': 99})
        self.assertEqual(stale['status'], 'failed')
        self.r.processes[42]['uid'] = 0
        protected = self.act('freeze', target=dict(IDENTITY))
        self.assertEqual(protected['status'], 'failed')
        self.assertEqual(self.r.signals, [])

    def test_pid_reuse_before_manual_kill_changes_nothing(self):
        operation = self.freeze()
        self.r.processes[42]['start_ticks'] = 200
        with patch.object(Actions, 'firewall') as firewall:
            result = self.act('kill', operation_id=operation)
        firewall.assert_not_called()
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)

    def test_operation_cannot_be_borrowed_from_another_case(self):
        operation = self.freeze()
        self.r.store.create_case(case_id='C2', title='Other case', actor=self.r.actor)
        params = self.params('kill', operation_id=operation)
        params['expected_sequence'] = self.r.store.get_case('C2')['last_sequence']
        result = self.client.request_action('C2', 'kill', **params)
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)

    def test_kill_only_recovery_keeps_its_original_scope(self):
        operation = self.freeze()
        with patch.object(Actions, 'kill', side_effect=RuntimeError('interrupted')):
            result = self.act('kill', operation_id=operation)
        self.assertEqual(result['status'], 'failed')
        state = self.r.store.load_state()
        self.assertFalse(state['cases'][operation]['isolate_requested'])
        with patch.object(Actions, 'firewall') as firewall:
            Workflow(self.r).tick(state)
        firewall.assert_not_called()
        self.assertIn((42, signal.SIGKILL), self.r.signals)

    def test_shared_undo_releases_only_requesting_case(self):
        state = {'cases': {}, 'resources': {}}
        with patch.object(Actions, 'firewall'):
            Actions(self.r).reversible(state, 'isolate', 'host', 'C1', True)
            Actions(self.r).reversible(state, 'isolate', 'host', 'C2', True)
        with patch.object(Actions, 'firewall') as firewall:
            result = self.act('undo', resource_key='isolate:host')
        firewall.assert_not_called()
        self.assertEqual(result['result']['remaining_owners'], ['C2'])
        self.assertFalse(result['result']['restriction_removed'])

    def test_event_delivery_requires_service_role_and_ack_preserves_history(self):
        with self.assertRaises(GatewayError):
            self.client.outbox()
        connector = self.make_client('connector', 'service')
        items = connector.outbox()['items']
        ids = [x['event_id'] for x in items]
        connector.acknowledge(ids)
        self.assertEqual(connector.outbox()['items'], [])
        self.assertTrue(self.client.timeline('C1')['items'])

    def test_ack_failure_rolls_back_the_whole_batch(self):
        connector = self.make_client('connector', 'service')
        event_id = connector.outbox()['items'][0]['event_id']
        with self.assertRaises(GatewayError):
            connector.acknowledge([event_id, 'unknown-event'])
        self.assertIn(event_id, [x['event_id'] for x in connector.outbox()['items']])

    def test_disabled_gateway_or_bad_page_cannot_execute(self):
        self.r.config['m6_gateway']['enabled'] = False
        with self.assertRaises(GatewayError) as caught:
            self.client.list_cases()
        self.assertEqual(caught.exception.code, 'disabled')
        self.r.config['m6_gateway']['enabled'] = True
        for page in ({'limit': True}, {'offset': -1}, {'limit': 101}):
            with self.subTest(page=page), self.assertRaises(GatewayError):
                self.client.list_cases(**page)

    def test_tampered_request_wrong_endpoint_and_expired_request_rejected(self):
        self.client.list_cases()
        original = self.requests[-1]
        packets = [original | {'method': 'request_action'}, signed(original | {'agent_id': '002'}, KEY),
                   signed(original | {'sent_at': '2020-01-01T00:00:00Z',
                                      'expires_at': '2020-01-01T00:01:00Z'}, KEY)]
        for packet in packets:
            with self.subTest(packet=packet):
                response = self.gateway.handle(packet)
                self.assertFalse(response['ok'])
                verify_signature(response, KEY)
        self.assertEqual(self.r.signals, [])

    def test_unknown_roles_and_future_lifetime_are_rejected(self):
        self.client.list_cases()
        original = self.requests[-1]
        for changes in ({'principal': {'type': 'user', 'id': 'x', 'roles': ['invented-admin']}},
                        {'expires_at': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()}):
            response = self.gateway.handle(signed(original | changes, KEY))
            self.assertFalse(response['ok'])

    def test_client_rejects_forged_response_and_mismatched_transport_request(self):
        self.client.list_cases()
        packet = self.requests[-1]
        response = self.gateway.handle(packet)
        for body in (response | {'ok': True, 'result': {'fake': True}},
                     signed(response | {'request_id': 'wrong-request'}, KEY)):
            with self.subTest(body=body), self.assertRaises(GatewayError):
                self.make_client(transport=lambda _: canonical(body)).list_cases()

    def test_ssh_transport_uses_fixed_command_and_keeps_json_out_of_shell_arguments(self):
        transport = SSHTransport('endpoint.example', 'ai-rdr-m6', '/keys/client', known_hosts_file='/keys/known_hosts')
        payload = '{"reason":"literal data"}'
        with patch('ai_rdr_m6.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='{}')) as run:
            self.assertEqual(transport(payload), '{}')
        args, kwargs = run.call_args
        self.assertFalse(kwargs['shell'])
        self.assertEqual(kwargs['input'], payload + '\n')
        self.assertNotIn(payload, args[0])
        self.assertIn('StrictHostKeyChecking=yes', args[0])
        self.assertEqual(args[0][-1], SSHTransport.COMMAND)

    def test_transport_timeout_is_uncertain_not_success(self):
        transport = SSHTransport('endpoint.example', 'ai-rdr-m6', '/keys/client')
        with patch('ai_rdr_m6.subprocess.run', side_effect=subprocess.TimeoutExpired('ssh', 1)):
            with self.assertRaises(GatewayError) as caught:
                transport('{}')
        self.assertEqual(caught.exception.code, 'transport_uncertain')


if __name__ == '__main__':
    unittest.main()

import concurrent.futures
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ai_rdr_aicm import CaseStore, Conflict, correlate_case
from ai_rdr_response import wazuh
from freeze_verify_manager import Workflow
from test_response import FakeRuntime


ACTOR = {'type': 'service', 'id': 'test:agent-001'}
ANALYST = {'type': 'user', 'id': 'analyst-5'}


class AICMTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = CaseStore(self.directory / 'cases.sqlite3')
        self.store.create_case(actor=ACTOR, title='Ransomware candidate', case_id='C1')

    def alert(self, source_id='A1', case_id='C1', **metadata):
        return self.store.attach_alert(case_id, producer='wazuh', agent_id='001',
            source_id=source_id, occurred_at='2026-10-12T12:00:00+04:00', metadata=metadata, actor=ACTOR)

    def operation(self, case_id='C1', status='FROZEN'):
        return {'case_id': case_id, 'status': status,
                'root': {'pid': 42, 'start_ticks': 100, 'boot_id': 'boot'},
                'processes': [], 'score': .75}

    def test_case_defaults_and_initial_audit(self):
        case = self.store.get_case('C1')
        self.assertEqual((case['lifecycle'], case['disposition'], case['version']), ('open', 'undetermined', 1))
        self.assertEqual(self.store.timeline('C1')[0]['event_type'], 'case.created')

    def test_alert_retries_deduplicated(self):
        key = self.alert(score=.75)
        self.assertEqual(self.alert(score=.75), key)
        self.assertEqual(len(self.store.get_case('C1')['alerts']), 1)
        self.assertEqual(len(self.store.timeline('C1')), 2)

    def test_source_id_changed_content_rejected(self):
        self.alert(score=.75)
        with self.assertRaises(Conflict):
            self.alert(score=.8)
        self.assertEqual(len(self.store.timeline('C1')), 2)

    def test_multiple_alerts_and_case_association(self):
        self.alert('A1')
        self.alert('A2')
        self.alert('A1', case_id='C2')
        self.assertEqual(len(self.store.get_case('C1')['alerts']), 2)
        self.assertEqual(len(self.store.get_case('C2')['alerts']), 1)

    def test_source_and_recording_times_distinct(self):
        self.alert()
        alert = self.store.get_case('C1')['alerts'][0]
        self.assertEqual(alert['occurred_at'], '2026-10-12T08:00:00Z')
        self.assertNotEqual(alert['occurred_at'], alert['recorded_at'])

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            self.store.attach_alert('C1', producer='wazuh', agent_id='001', source_id='A1',
                                    occurred_at='2026-10-12T08:00:00', metadata={}, actor=ACTOR)

    def test_nested_secrets_redacted(self):
        self.alert(context={'api_token': 'secret-value', 'username': 'labuser'})
        self.store.append_event('C1', 'test.event', actor=ACTOR,
                                 details={'credentials': 'hidden', 'nested': {'password': 'hidden'}})
        exported = json.dumps(self.store.export_case('C1'))
        self.assertNotIn('secret-value', exported)
        self.assertNotIn('hidden', exported)
        self.assertIn('labuser', exported)
        self.assertIn('[REDACTED]', exported)

    def test_case_edit_and_audit_commit_together(self):
        with patch.object(self.store, '_event', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Triage', lifecycle='investigating')
        self.assertEqual(self.store.get_case('C1')['lifecycle'], 'open')
        self.assertEqual(len(self.store.timeline('C1')), 1)

    def test_stale_update_rejection_is_audited(self):
        self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Triage', lifecycle='investigating')
        with self.assertRaises(Conflict):
            self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Stale', severity='high')
        case = self.store.get_case('C1')
        self.assertEqual(case['severity'], 'medium')
        event = self.store.timeline('C1')[-1]
        self.assertEqual((event['event_type'], event['outcome']), ('case.update_rejected', 'failure'))

    def test_lifecycle_disposition_and_response_independent(self):
        state = {'cases': {'O1': self.operation(status='THAWED')}, 'resources': {}}
        self.store.save_state(state, actor=ACTOR)
        case = self.store.get_case('C1')
        self.assertEqual((case['lifecycle'], case['disposition']), ('open', 'undetermined'))
        self.assertEqual(case['operations'][0]['status'], 'THAWED')

    def test_close_and_reopen_with_reason(self):
        self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Confirmed benign',
                               lifecycle='resolved', disposition='benign')
        self.store.update_case('C1', actor=ANALYST, expected_version=2, reason='Review complete', lifecycle='closed')
        self.assertEqual(self.store.get_case('C1')['closure_reason'], 'Review complete')
        self.store.update_case('C1', actor=ANALYST, expected_version=3, reason='New evidence', lifecycle='investigating')
        self.assertIsNone(self.store.get_case('C1')['closed_at'])

    def test_cannot_close_with_active_response(self):
        self.store.save_state({'cases': {'O1': self.operation()}, 'resources': {}}, actor=ACTOR)
        self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Review', lifecycle='resolved')
        with self.assertRaises(Conflict):
            self.store.update_case('C1', actor=ANALYST, expected_version=2, reason='Premature', lifecycle='closed')

    def test_duplicate_case_keeps_its_history_and_avoids_cycles(self):
        self.store.create_case(actor=ACTOR, title='Canonical incident', case_id='C2')
        self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Same incident',
                               disposition='duplicate', duplicate_of='C2')
        self.assertEqual(self.store.get_case('C1')['duplicate_of'], 'C2')
        with self.assertRaises(Conflict):
            self.store.update_case('C2', actor=ANALYST, expected_version=1, reason='Cycle',
                                   disposition='duplicate', duplicate_of='C1')

    def test_state_operations_and_audit_roll_back_together(self):
        state = {'cases': {'O1': self.operation(status='PREPARING')}, 'resources': {}}
        self.store.save_state(state, actor=ACTOR)
        previous_events = self.store.timeline('C1')
        state['cases']['O1']['status'] = 'FROZEN'
        with patch.object(self.store, '_event', side_effect=sqlite3.OperationalError('audit unavailable')):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.save_state(state, actor=ACTOR)
        self.assertEqual(self.store.load_state()['cases']['O1']['status'], 'PREPARING')
        self.assertEqual(self.store.get_case('C1')['operations'][0]['status'], 'PREPARING')
        self.assertEqual(self.store.timeline('C1'), previous_events)

    def test_multiple_operations_do_not_overwrite(self):
        state = {'cases': {'O1': self.operation(), 'O2': self.operation(status='REVIEW')}, 'resources': {}}
        self.store.save_state(state, actor=ACTOR)
        self.assertEqual(len(self.store.get_case('C1')['operations']), 2)

    def test_no_op_save_does_not_add_events(self):
        state = {'cases': {'O1': self.operation()}, 'resources': {}}
        self.store.save_state(state, actor=ACTOR)
        events = self.store.timeline('C1')
        self.store.save_state(state, actor=ACTOR)
        self.assertEqual(self.store.timeline('C1'), events)

    def test_sql_update_delete_audit_forbidden(self):
        with self.store.connection() as db:
            for statement in ('UPDATE audit_events SET event_type="edited"', 'DELETE FROM audit_events'):
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(statement)

    def test_concurrent_writers_have_unique_contiguous_sequence(self):
        def write(i):
            return self.store.append_event('C1', 'test.concurrent', actor=ACTOR, details={'i': i})
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            events = list(pool.map(write, range(24)))
        timeline = self.store.timeline('C1')
        self.assertEqual([x['case_sequence'] for x in timeline], list(range(1, 26)))
        self.assertEqual(len({x['event_id'] for x in events}), 24)

    def test_outbox_ack_idempotent_and_does_not_delete_history(self):
        event = self.store.pending_events()[0]
        self.store.acknowledge([event['event_id']])
        self.store.acknowledge([event['event_id']])
        self.assertEqual(self.store.pending_events(), [])
        self.assertEqual(len(self.store.timeline('C1')), 1)

    def test_outbox_ack_batch_rolls_back_on_unknown_event(self):
        event = self.store.pending_events()[0]
        with self.assertRaises(KeyError):
            self.store.acknowledge([event['event_id'], 'not-a-real-event'])
        self.assertEqual(len(self.store.pending_events()), 1)

    def test_delivery_retry_after_lost_ack_is_idempotent(self):
        receiver = CaseStore(self.directory / 'central.sqlite3')
        event = self.store.pending_events()[0]
        self.assertTrue(receiver.ingest_event(event, received_by=ACTOR))
        self.assertFalse(receiver.ingest_event(event, received_by=ACTOR))
        self.store.acknowledge([event['event_id']])
        imported = [x for x in receiver.timeline('C1') if x['event_id'] == event['event_id']]
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0]['occurred_at'], event['occurred_at'])
        self.assertEqual(imported[0]['details']['delivery']['origin_sequence'], 1)

    def test_delivery_id_collision_rejected(self):
        receiver = CaseStore(self.directory / 'central.sqlite3')
        event = self.store.pending_events()[0]
        receiver.ingest_event(event, received_by=ACTOR)
        changed = dict(event, details={'changed': True})
        with self.assertRaises(Conflict):
            receiver.ingest_event(changed, received_by=ACTOR)

    def test_evidence_reference_idempotent_and_no_raw_payload(self):
        values = dict(evidence_id='E1', kind='decoy_write', reference='audit:agent-001:event-7',
                      metadata={'digest': 'sha256:example'}, actor=ACTOR)
        self.store.attach_evidence('C1', **values)
        self.store.attach_evidence('C1', **values)
        self.assertEqual(len(self.store.get_case('C1')['evidence']), 1)
        with self.assertRaises(Conflict):
            self.store.attach_evidence('C1', **(values | {'reference': 'different'}))

    def test_backup_restore_includes_complete_audit(self):
        self.alert()
        destination = self.directory / 'backup.sqlite3'
        self.store.backup(destination)
        restored = CaseStore(destination)
        self.assertEqual(restored.get_case('C1'), self.store.get_case('C1'))
        self.assertEqual(restored.timeline('C1'), self.store.timeline('C1'))

    def test_security_audit_does_not_create_incident(self):
        self.store.append_event(None, 'request.rejected', actor=ACTOR, outcome='failure')
        self.assertEqual(len(self.store.list_cases()), 1)
        self.assertEqual(len(self.store.timeline(None)), 1)

    def test_future_schema_fails_closed(self):
        with self.store.connection() as db:
            db.execute('PRAGMA user_version=99')
        with self.assertRaises(RuntimeError):
            CaseStore(self.store.path)

    def test_invalid_actor_cannot_create_case(self):
        with self.assertRaises(ValueError):
            self.store.create_case(title='Invalid', actor={'type': 'user'}, case_id='C2')
        with self.assertRaises(KeyError):
            self.store.get_case('C2')

    def test_correlation_uses_immutable_identity_not_host_time(self):
        values = dict(agent_id='001', producer='wazuh', process={'pid': 42, 'start_ticks': 100, 'boot_id': 'boot'})
        key = correlate_case(**values, source_id='A1')
        self.assertEqual(key, correlate_case(**values, source_id='A2'))
        self.assertNotEqual(key, correlate_case(**(values | {'process': {'pid': 42, 'start_ticks': 101, 'boot_id': 'boot'}})))

    def test_alert_only_correlation_requires_source_identity(self):
        self.assertEqual(correlate_case(agent_id='001', producer='wazuh', source_id='A1'),
                         correlate_case(agent_id='001', producer='wazuh', source_id='A1'))
        with self.assertRaises(ValueError):
            correlate_case(agent_id='001', producer='wazuh')

    def test_closed_incident_cannot_launch_response(self):
        self.store.update_case('C1', actor=ANALYST, expected_version=1, reason='Review', lifecycle='resolved')
        self.store.update_case('C1', actor=ANALYST, expected_version=2, reason='Complete', lifecycle='closed')
        with self.assertRaises(Conflict):
            self.store.save_state({'cases': {'O1': self.operation(status='PREPARING')}, 'resources': {}}, actor=ACTOR)
        self.assertIsNone(self.store.load_state())


class ARMIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.r = FakeRuntime(self.directory)

    def send(self, pid=42, alert_id='A1', command='add'):
        payload = {'command': command, 'parameters': {'alert': {'id': alert_id,
            'agent': {'id': '001'}, 'timestamp': '2026-10-12T08:00:00Z',
            'data': {'case_id': 'C1', 'pid': pid, 'start_ticks': 100, 'boot_id': 'boot', 'risk_score': .75}}}}
        incoming = io.StringIO(json.dumps(payload) + '\n' + ('{"command":"continue"}\n' if command == 'add' else ''))
        wazuh(self.r, 'freeze', incoming, io.StringIO())

    def test_alert_to_case_and_verified_response_timeline(self):
        self.send()
        case = self.r.store.get_case('C1')
        self.assertEqual(len(case['alerts']), 1)
        self.assertEqual(case['operations'][0]['status'], 'FROZEN')
        self.assertEqual(case['disposition'], 'undetermined')
        events = self.r.store.timeline('C1')
        phases = [x['details']['after'] for x in events if x['event_type'] == 'response.state_changed']
        self.assertIn('PREPARING', phases)
        self.assertIn('FROZEN', phases)
        self.assertTrue(any(x['request_id'] for x in events))

    def test_wazuh_two_roots_in_one_case(self):
        self.r.processes[43] = dict(self.r.processes[42], pid=43)
        self.send()
        self.send(pid=43, alert_id='A2')
        case = self.r.store.get_case('C1')
        self.assertEqual(len(case['operations']), 2)
        self.assertEqual({x['target']['pid'] for x in case['operations']}, {42, 43})
        with self.r.transaction() as state:
            with self.assertRaises(ValueError):
                Workflow(self.r).thaw(state, 'C1', 'ambiguous')
            key = next(k for k, v in state['cases'].items() if v['root']['pid'] == 42)
            Workflow(self.r).thaw(state, 'C1', 'benign', operation_id=key)
        self.assertEqual(self.r.identity(42)['state'], 'S')
        self.assertEqual(self.r.identity(43)['state'], 'T')

    def test_timer_delete_uses_original_operation(self):
        self.send()
        self.send(command='delete')
        self.assertEqual(self.r.store.get_case('C1')['operations'][0]['status'], 'THAWED')

    def test_duplicate_alert_does_not_create_new_operation(self):
        self.send()
        self.send()
        case = self.r.store.get_case('C1')
        self.assertEqual(len(case['alerts']), 1)
        self.assertEqual(len(case['operations']), 1)
        self.assertEqual(len(self.r.signals), 1)

    def test_legacy_state_migrates_once_and_retains_archive(self):
        legacy = {'cases': {'C1': {'status': 'THAWED', 'root': self.r.identity(42)}}, 'resources': {}}
        path = self.directory / 'state.json'
        path.write_text(json.dumps(legacy))
        with self.r.transaction() as state:
            self.assertEqual(state, legacy)
        self.assertTrue(path.exists())
        path.write_text('stale archive no longer authoritative')
        with self.r.transaction() as state:
            self.assertEqual(state, legacy)
        self.assertEqual(self.r.store.get_case('C1')['operations'][0]['status'], 'THAWED')

    def test_audit_failure_prevents_unjournaled_signal(self):
        with patch.object(self.r.store, 'save_state', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(sqlite3.OperationalError):
                self.send()
        self.assertEqual(self.r.signals, [])

    def test_malformed_input_is_security_audited(self):
        with self.assertRaises(ValueError):
            wazuh(self.r, 'freeze', io.StringIO('[]\n'), io.StringIO())
        self.assertEqual(self.r.store.timeline(None)[0]['event_type'], 'response.request_rejected')

    def test_inconclusive_timeout_never_becomes_benign(self):
        self.send()
        with self.r.transaction() as state:
            record = next(iter(state['cases'].values()))
            record['deadline'] = 0
            Workflow(self.r).tick(state)
        case = self.r.store.get_case('C1')
        self.assertEqual(case['operations'][0]['status'], 'THAWED')
        self.assertEqual(case['disposition'], 'undetermined')

    def test_missing_case_id_generates_stable_process_case(self):
        def send(alert_id):
            alert = {'id': alert_id, 'agent': {'id': '001'}, 'timestamp': '2026-10-12T08:00:00Z',
                     'data': {'pid': 42, 'start_ticks': 100, 'boot_id': 'boot', 'risk_score': .75}}
            payload = {'command': 'add', 'parameters': {'alert': alert}}
            wazuh(self.r, 'freeze', io.StringIO(json.dumps(payload) + '\n{"command":"continue"}\n'), io.StringIO())
        send('A1')
        send('A2')
        cases = self.r.store.list_cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(len(self.r.store.get_case(cases[0]['case_id'])['alerts']), 2)
        self.assertEqual(len(self.r.signals), 1)

    def test_no_effect_for_nested_malformed_input(self):
        with self.assertRaises((TypeError, AttributeError)):
            wazuh(self.r, 'freeze', io.StringIO('{"parameters":null,"command":"add"}\n'), io.StringIO())
        self.assertEqual(len(self.r.store.timeline(None)), 1)
        self.assertEqual(self.r.signals, [])

    def test_sqlite_corruption_never_falls_back_to_old_json(self):
        (self.directory / 'aicm.sqlite3').write_text('corrupt')
        (self.directory / 'state.json').write_text('{"cases":{},"resources":{}}')
        with self.assertRaises(sqlite3.DatabaseError):
            with self.r.transaction():
                pass

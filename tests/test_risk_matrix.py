"""Risk scenarios and the real Wazuh/AICM boundary; OS actions are simulated."""
from copy import deepcopy
import datetime as dt
import io
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_rdr_aicm import CaseStore, Conflict
from ai_rdr_actions import Actions
from ai_rdr_response import wazuh
from ai_rdr_risk import RiskMatrix, decision_id
from freeze_verify_manager import Workflow
from test_response import FakeRuntime


NOW = dt.datetime(2026, 11, 11, 10, tzinfo=dt.timezone.utc)
IDENTITY = {'pid': 42, 'start_ticks': 100, 'boot_id': 'boot'}
ACTOR = {'type': 'service', 'id': 'test-matrix'}


def bundle():
    return {'case_id': 'RISK-1', 'agent_id': '001', **IDENTITY,
            'ml': {'ransomware_probability': .98, 'threshold': .13, 'alert': True,
                   'prediction': 'ransomware', 'response_mode': 'alert_only'}}


def decoy():
    return {'type': 'decoy_write', 'event_id': 'AUDIT-1', **IDENTITY}


def intel(now=NOW):
    return {'status': 'match', 'malicious': True, 'provider': 'labelled-test-fixture',
            'checked_at': now.isoformat(), 'indicator_type': 'ip', 'indicator': '192.0.2.99',
            'process': dict(IDENTITY)}


class MatrixTests(unittest.TestCase):
    def evaluate(self, data=None, config=None, at=NOW):
        return RiskMatrix(config).evaluate(bundle() if data is None else data, now=at,
                                           occurred_at=NOW.isoformat(), source_id='A1')

    def test_ml_alone_is_suspicious_without_response(self):
        result = self.evaluate()
        self.assertEqual((result['risk_level'], result['action']), ('suspicious', 'record_only'))
        self.assertLess(result['score'], 70)
        self.assertFalse(result['execution_allowed'])

    def test_native_threshold_not_legacy_candidate_threshold(self):
        data = bundle()
        data['ml']['ransomware_probability'] = .17
        result = self.evaluate(data)
        self.assertEqual(result['risk_level'], 'suspicious')
        self.assertEqual(result['evidence'][0]['reason'], 'model_positive')
        data['ml'].update(ransomware_probability=.73, threshold=.8, alert=False, prediction='benign')
        self.assertEqual(self.evaluate(data)['risk_level'], 'normal')

    def test_flat_and_nested_model_contracts_score_equally(self):
        data = bundle()
        model = data.pop('ml')
        data.update(model)
        self.assertEqual(self.evaluate(data)['score'], self.evaluate()['score'])

    def test_missing_mode_defaults_to_alert_only_even_with_outer_override(self):
        data = bundle()
        del data['ml']['response_mode']
        data['response_mode'] = 'automatic'
        self.assertEqual(self.evaluate(data)['response_mode'], 'alert_only')

    def test_ambiguous_and_nonfinite_models_rejected(self):
        for changes in ({'risk_score': .75}, {'ransomware_probability': .9},
                        {'ml': {'ransomware_probability': True, 'threshold': .13}},
                        {'ml': {'ransomware_probability': float('nan'), 'threshold': .13}},
                        {'ml': {'ransomware_probability': .9, 'threshold': .13, 'alert': False}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.evaluate(bundle() | changes)

    def test_honeyfile_without_pid_never_identifies_a_process(self):
        data = {'agent_id': '001', 'honeyfile': {'decoy_id': 'd1', 'path': '/lab/decoy', 'operation': 'WRITE'}}
        result = self.evaluate(data)
        self.assertEqual(result['risk_level'], 'suspicious')
        self.assertIsNone(result['process'])
        self.assertEqual(result['action'], 'record_only')

    def test_host_time_link_does_not_increase_process_score(self):
        data = bundle() | {'honeyfile': {'decoy_id': 'd1', 'operation': 'WRITE'}}
        result = self.evaluate(data)
        self.assertEqual(result['score'], self.evaluate()['score'])
        self.assertEqual(result['correlation'], 'possible_link')
        self.assertEqual(result['action'], 'record_only')

    def test_attributed_decoy_is_independent_and_high_without_ml(self):
        result = self.evaluate({'agent_id': '001', **IDENTITY, 'evidence': decoy()})
        self.assertEqual((result['risk_level'], result['score'], result['action']), ('high', 95, 'freeze'))
        self.assertEqual(result['next_step'], 'contain')

    def test_bad_optional_model_does_not_disable_attributed_decoy(self):
        result = self.evaluate(bundle() | {'ml': {'threshold': .13}, 'evidence': decoy()})
        self.assertEqual(result['risk_level'], 'high')
        self.assertTrue(result['invalid_sources'])

    def test_read_with_pid_does_not_grant_write_authority(self):
        result = self.evaluate(bundle() | {'honeyfile': {'operation': 'READ', **IDENTITY}})
        self.assertEqual(result['risk_level'], 'suspicious')
        self.assertNotEqual(result['next_step'], 'contain')

    def test_explicitly_unregistered_write_cannot_authorise_containment(self):
        result = self.evaluate(bundle() | {'evidence': decoy() | {'registered': False}})
        self.assertEqual(result['risk_level'], 'suspicious')
        self.assertEqual(result['action'], 'record_only')

    def test_unrelated_process_or_endpoint_is_excluded(self):
        for changes in ({'pid': 43}, {'start_ticks': 200}, {'boot_id': 'other'}):
            evidence = decoy() | changes
            result = self.evaluate(bundle() | {'evidence': evidence})
            self.assertEqual(result['score'], self.evaluate()['score'])
        result = self.evaluate(bundle() | {'honeyfile': {'operation': 'WRITE', 'agent_id': '002'}})
        self.assertEqual(result['score'], self.evaluate()['score'])

    def test_explicit_same_process_ioc_can_corroborate(self):
        result = self.evaluate(bundle() | {'src_ip': '192.0.2.99', 'threat_intel': intel()})
        self.assertEqual(result['risk_level'], 'high')
        self.assertEqual(result['correlation'], 'same_process')
        self.assertTrue(result['corroborated'])
        self.assertEqual(result['response_mode'], 'alert_only')

    def test_block_action_requires_an_ip_bound_to_the_scored_process(self):
        cfg = {'risk_matrix': {'high_action': 'block'}}
        data = bundle() | {'src_ip': '192.0.2.99', 'evidence': decoy()}
        self.assertEqual(self.evaluate(data, cfg)['action'], 'record_only')
        data['threat_intel'] = intel()
        self.assertEqual(self.evaluate(data, cfg)['action'], 'block')

    def test_context_free_ioc_does_not_corroborate_process(self):
        ti = intel()
        del ti['process']
        result = self.evaluate(bundle() | {'src_ip': '192.0.2.99', 'threat_intel': ti})
        self.assertEqual(result['risk_level'], 'suspicious')

    def test_ti_age_skew_and_entity_matching_are_enforced(self):
        for ti in (intel(NOW - dt.timedelta(seconds=901)), intel(NOW + dt.timedelta(seconds=31)),
                   intel() | {'indicator': '192.0.2.100'}, intel() | {'process': IDENTITY | {'pid': 43}},
                   intel() | {'provider': ''}, {'reputation': 'Malicious', 'indicator': '192.0.2.99'}):
            with self.subTest(ti=ti):
                self.assertEqual(self.evaluate(bundle() | {'src_ip': '192.0.2.99', 'threat_intel': ti})['risk_level'],
                                 'suspicious')

    def test_no_match_is_not_a_clean_verdict_or_missing_response(self):
        result = self.evaluate({'agent_id': '001', 'threat_intel': {'status': 'no_match'}})
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertNotIn('threat_intel', result['missing_sources'])
        self.assertTrue(result['partial_evidence'])

    def test_shared_m1_ml_group_does_not_double_count_telemetry(self):
        data = bundle() | {'monitoring': {'event_id': 'W1', 'rule_level': 16,
                                         'suspicious': True, 'process': dict(IDENTITY)}}
        result = self.evaluate(data)
        self.assertEqual(result['score'], self.evaluate()['score'])
        self.assertEqual(result['correlation'], 'same_process')
        self.assertFalse(result['corroborated'])

    def test_duplicate_records_do_not_inflate_score_and_conflicts_rejected(self):
        raw = {'event_id': 'W1', 'rule_level': 16, 'suspicious': True, 'process': dict(IDENTITY)}
        data = bundle() | {'monitoring': [raw, deepcopy(raw)]}
        self.assertEqual(len([e for e in self.evaluate(data)['evidence'] if e['source'] == 'monitoring']), 1)
        data['monitoring'][1]['rule_level'] = 15
        with self.assertRaises(ValueError):
            self.evaluate(data)

    def test_conflicting_ti_ids_are_not_silently_treated_as_provider_outage(self):
        ti = intel() | {'event_id': 'TI-1'}
        data = bundle() | {'src_ip': '192.0.2.99', 'threat_intel': [ti, ti | {'provider': 'different'}]}
        with self.assertRaises(ValueError):
            self.evaluate(data)

    def test_outside_correlation_window_does_not_corroborate(self):
        data = bundle() | {'src_ip': '192.0.2.99', 'threat_intel': intel()}
        data['ml']['timestamp'] = (NOW - dt.timedelta(seconds=6)).isoformat()
        self.assertEqual(self.evaluate(data)['risk_level'], 'suspicious')

    def test_missing_or_stale_inputs_are_not_normal(self):
        self.assertEqual(self.evaluate({'agent_id': '001'})['risk_level'], 'unknown')
        data = bundle()
        data['ml']['timestamp'] = (NOW - dt.timedelta(seconds=31)).isoformat()
        self.assertEqual(self.evaluate(data)['risk_level'], 'unknown')

    def test_configuration_changes_scores_and_decision_identity(self):
        original = self.evaluate()
        result = self.evaluate(config={'risk_matrix': {'version': 'experiment-2', 'weights': {'ml': 45}}})
        self.assertLess(result['score'], original['score'])
        self.assertNotEqual(result['decision_id'], original['decision_id'])

    def test_decision_replay_identity_ignores_only_evaluation_time(self):
        self.assertEqual(self.evaluate()['decision_id'], self.evaluate(at=NOW + dt.timedelta(seconds=1))['decision_id'])

    def test_narrow_expiring_benign_guard_is_logged_but_not_a_decoy_bypass(self):
        guard = {'id': 'backup', 'agent_id': '001', 'sha256': 'a' * 64,
                 'process_name': 'backup', 'expires_at': (NOW + dt.timedelta(hours=1)).isoformat()}
        cfg = {'risk_matrix': {'benign_guards': [guard]}}
        data = bundle() | {'sha256': 'a' * 64, 'process_name': 'backup'}
        result = self.evaluate(data, cfg)
        self.assertEqual((result['risk_level'], result['suppressed_by']), ('normal', 'backup'))
        self.assertEqual(self.evaluate(data | {'evidence': decoy()}, cfg)['risk_level'], 'high')
        guard['expires_at'] = (NOW - dt.timedelta(seconds=1)).isoformat()
        self.assertEqual(self.evaluate(data, cfg)['risk_level'], 'suspicious')

    def test_invalid_configuration_is_rejected(self):
        for config in ({'bands': {'high': 20}}, {'weights': {'ml': True}}, {'weights': {'ml': float('inf')}},
                       {'high_action': 'kill'}, {'allow_single_signal': 'true'}, {'unknown': 1},
                       {'benign_guards': [{'id': 'any-backup'}]}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                RiskMatrix({'risk_matrix': config})

    def test_file_configuration_is_loaded_and_ambiguous_sources_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'matrix.json'
            path.write_text(json.dumps({'version': 'file-policy', 'weights': {'ml': 40}}))
            matrix = RiskMatrix({'risk_matrix_file': str(path)})
            self.assertEqual(matrix.policy['version'], 'file-policy')
            with self.assertRaises(ValueError):
                RiskMatrix({'risk_matrix_file': str(path), 'risk_matrix': {'version': 'other'}})


class FusionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.r = FakeRuntime(Path(self.folder.name))
        self.r.config.update(agent_id='001', automatic_actions=['freeze'])

    def send(self, data=None, source='A1', command='add'):
        data = bundle() if data is None else data
        payload = {'command': command, 'parameters': {'alert': {'id': source, 'agent': {'id': '001'},
                   'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(), 'data': data}}}
        # Stable source metadata on retries, including the event timestamp.
        payload['parameters']['alert']['timestamp'] = getattr(self, 'event_timestamp', payload['parameters']['alert']['timestamp'])
        self.event_timestamp = payload['parameters']['alert']['timestamp']
        incoming = io.StringIO(json.dumps(payload) + '\n' + ('{"command":"continue"}\n' if command == 'add' else ''))
        outgoing = io.StringIO()
        wazuh(self.r, 'fusion', incoming, outgoing)
        return self.r.store.timeline('RISK-1'), outgoing.getvalue()

    def latest(self, events):
        return [e['details']['decision'] for e in events if e['event_type'] == 'risk.decided'][-1]

    def correlated(self, mode='alert_only'):
        data = bundle() | {'src_ip': '192.0.2.99', 'threat_intel': intel(dt.datetime.now(dt.timezone.utc))}
        data['ml']['response_mode'] = mode
        return data

    def test_suspicious_ml_is_recorded_without_freeze(self):
        events, _ = self.send()
        self.assertEqual(self.latest(events)['action'], 'record_only')
        self.assertEqual(self.r.signals, [])
        self.assertFalse(self.r.store.get_case('RISK-1')['operations'])

    def test_high_score_cannot_override_m2_alert_only(self):
        events, _ = self.send(self.correlated())
        decision = self.latest(events)
        self.assertEqual(decision['risk_level'], 'high')
        self.assertTrue(decision['target_identified'])
        self.assertFalse(decision['automatic_response_allowed'])
        self.assertEqual(self.r.signals, [])

    def test_normal_case_is_low_severity_and_never_executes(self):
        data = bundle()
        data['ml'].update(ransomware_probability=.01, alert=False, prediction='benign')
        events, _ = self.send(data)
        self.assertEqual(self.latest(events)['risk_level'], 'normal')
        self.assertEqual(self.r.store.get_case('RISK-1')['severity'], 'low')
        self.assertEqual(self.r.signals, [])

    def test_missing_m2_mode_does_not_inherit_outer_automatic(self):
        data = self.correlated()
        del data['ml']['response_mode']
        data['response_mode'] = 'automatic'
        self.send(data)
        self.assertEqual(self.r.signals, [])

    def test_permitted_high_risk_freezes_and_waits_for_review(self):
        events, _ = self.send(self.correlated('automatic'))
        decision = self.latest(events)
        self.assertTrue(decision['execution_allowed'])
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])
        record = next(iter(self.r.store.load_state()['cases'].values()))
        self.assertEqual(record['status'], 'REVIEW')
        self.assertEqual(record['risk_decision_id'], decision['decision_id'])
        record['deadline'] = 0
        state = self.r.store.load_state()
        with patch.object(Actions, 'firewall') as firewall:
            Workflow(self.r).tick(state)
        firewall.assert_not_called()
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)

    def test_attributed_decoy_runs_existing_freeze_verify_contain(self):
        with patch.object(Actions, 'firewall'):
            events, _ = self.send(bundle() | {'evidence': decoy()})
        self.assertTrue(self.latest(events)['automatic_response_allowed'])
        self.assertEqual([sig for _, sig in self.r.signals], [signal.SIGSTOP, signal.SIGKILL])

    def test_wrong_process_cannot_execute_even_with_high_score(self):
        self.r.processes[42]['start_ticks'] = 200
        events, _ = self.send(self.correlated('automatic'))
        self.assertFalse(self.latest(events)['target_identified'])
        self.assertEqual(self.r.signals, [])

    def test_host_action_also_requires_current_scored_process(self):
        self.r.config.update(risk_matrix={'high_action': 'isolate'}, automatic_actions=['isolate'])
        self.r.processes[42]['start_ticks'] = 200
        with patch.object(Actions, 'firewall') as firewall:
            events, _ = self.send(self.correlated('automatic'))
        firewall.assert_not_called()
        self.assertFalse(self.latest(events)['execution_allowed'])

    def test_configured_high_risk_ip_action_uses_existing_playbook(self):
        self.r.config.update(risk_matrix={'high_action': 'block'}, automatic_actions=['block'])
        with patch.object(Actions, 'firewall') as firewall:
            events, _ = self.send(self.correlated('automatic'))
        firewall.assert_called_once()
        self.assertEqual(self.latest(events)['action'], 'block')
        self.assertTrue(self.latest(events)['execution_allowed'])
        self.assertEqual(self.r.signals, [])

    def test_matrix_account_action_cannot_target_another_users_account(self):
        self.r.config.update(risk_matrix={'high_action': 'disable'}, automatic_actions=['disable'])
        with patch.object(Actions, 'account_snapshot', return_value={'uid': 1002}), \
                patch.object(Actions, 'account') as account:
            events, _ = self.send(self.correlated('automatic') | {'username': 'other-user'})
        account.assert_not_called()
        self.assertFalse(self.latest(events)['execution_allowed'])

    def test_decision_failure_prevents_all_os_effects(self):
        with patch.object(self.r.store, 'record_risk_decision', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(sqlite3.OperationalError):
                self.send(bundle() | {'evidence': decoy()})
        self.assertEqual(self.r.signals, [])

    def test_retries_do_not_duplicate_decision_or_host_effect(self):
        data = self.correlated('automatic')
        self.send(data)
        events, _ = self.send(data)
        self.assertEqual(len([e for e in events if e['event_type'] == 'risk.decided']), 1)
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP)])

    def test_new_attributed_evidence_upgrades_same_operation(self):
        self.send(self.correlated('automatic'))
        with patch.object(Actions, 'firewall'):
            self.send(bundle() | {'evidence': decoy()}, source='A2')
        self.assertEqual(len(self.r.store.get_case('RISK-1')['operations']), 2)  # process + isolation
        self.assertEqual([s for _, s in self.r.signals].count(signal.SIGSTOP), 1)
        self.assertIn((42, signal.SIGKILL), self.r.signals)

    def test_fusion_timer_delete_is_rejected(self):
        with self.assertRaises(ValueError):
            self.send(command='delete')
        self.assertEqual(self.r.signals, [])

    def test_forged_proof_cannot_authorise_another_process(self):
        events, _ = self.send(self.correlated('automatic'))
        decision = self.latest(events)
        self.r.processes[43] = dict(self.r.processes[42], pid=43, state='S')
        state = self.r.store.load_state()
        with self.assertRaises(ValueError):
            Workflow(self.r).freeze(state, 'RISK-1', 43, 100, 'boot', None,
                                    response_mode='automatic', risk_decision_id=decision['decision_id'])
        self.assertNotIn((43, signal.SIGSTOP), self.r.signals)


class DecisionStorageTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.store = CaseStore(Path(self.folder.name) / 'cases.sqlite3')
        self.decision = RiskMatrix().evaluate(bundle(), now=NOW, occurred_at=NOW.isoformat(), source_id='A1')

    def test_atomic_decision_outbox_and_severity_escalation(self):
        self.store.record_risk_decision(self.decision, actor=ACTOR)
        high = RiskMatrix().evaluate(bundle() | {'evidence': decoy()}, now=NOW, occurred_at=NOW.isoformat(), source_id='A2')
        self.store.record_risk_decision(high, actor=ACTOR)
        self.store.record_risk_decision(self.decision, actor=ACTOR)
        self.assertEqual(self.store.get_case('RISK-1')['severity'], 'high')
        self.assertEqual(len([e for e in self.store.pending_events() if e['event_type'] == 'risk.decided']), 2)
        self.assertEqual(self.store.risk_decision(high['decision_id'])['risk_level'], 'high')

    def test_storage_failure_rolls_back_decision_case_and_outbox(self):
        with patch.object(self.store, '_event', side_effect=sqlite3.OperationalError('full')):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.record_risk_decision(self.decision, actor=ACTOR)
        self.assertEqual(self.store.list_cases(), [])
        self.assertEqual(self.store.pending_events(), [])

    def test_same_id_different_body_is_rejected(self):
        self.store.record_risk_decision(self.decision, actor=ACTOR)
        changed = self.decision | {'score': 99}
        with self.assertRaises(Conflict):
            self.store.record_risk_decision(changed, actor=ACTOR)

    def test_preview_cli_does_not_create_state_or_require_root(self):
        root = Path(__file__).resolve().parents[1]
        command = [sys.executable, str(root / 'ai_rdr_risk.py'), '--input',
                   str(root / 'tests/fixtures/risk-matrix-example.json'), '--at', NOW.isoformat(),
                   '--matrix', str(root / 'config/risk-matrix.example.json')]
        result = subprocess.run(command, cwd=self.folder.name, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        decision = json.loads(result.stdout)
        self.assertEqual(decision['correlation'], 'possible_link')
        self.assertFalse(decision['execution_allowed'])
        self.assertEqual(list(Path(self.folder.name).iterdir()), [self.store.path])


if __name__ == '__main__':
    unittest.main()

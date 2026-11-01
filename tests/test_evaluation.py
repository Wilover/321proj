import datetime as dt
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_evaluate import (create_corpus, measure_damage, settings_checked, WazuhAPI,
                           NoRedirect, Probe, probes_effective, probes_restored,
                           finish_case, build_alert, response_received_ns, summarize, evaluate_one)
from m5_lab_host import LabRuntime
from ai_rdr_response import wazuh


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def corpus(self):
        return create_corpus(self.folder, settings_checked({'files': 3, 'file_bytes': 128}),
                             os.getuid(), os.getgid())

    def test_manifest_counts_unique_originals_and_rename_is_not_loss(self):
        manifest = self.corpus()
        first = self.folder / 'corpus/file-000000.bin'
        first.rename(first.with_suffix('.renamed'))
        measured = measure_damage(self.folder / 'corpus', manifest)
        self.assertEqual(measured['preserved_files'], 3)
        self.assertEqual(measured['damaged_files'], 0)

    def test_modified_deleted_and_encrypted_copy_are_distinguished(self):
        manifest = self.corpus()
        corpus = self.folder / 'corpus'
        (corpus / 'file-000000.bin').write_bytes(b'overwritten')
        (corpus / 'file-000001.bin').unlink()
        # A new ciphertext copy does not destroy the intact third original.
        (corpus / 'file-000002.encrypted').write_bytes(b'opaque copy')
        result = measure_damage(corpus, manifest)
        self.assertEqual(result['damaged_file_ids'], [0, 1])
        self.assertEqual(result['original_bytes_of_damaged_files'], 256)

    def test_content_matching_cannot_reuse_one_copy_for_two_originals(self):
        manifest = self.corpus()
        manifest['files'][1]['sha256'] = manifest['files'][0]['sha256']
        (self.folder / 'corpus/file-000001.bin').unlink()
        self.assertEqual(measure_damage(self.folder / 'corpus', manifest)['damaged_files'], 1)

    def test_links_and_fifo_are_not_followed_or_read(self):
        manifest = self.corpus()
        corpus = self.folder / 'corpus'
        outside = self.folder / 'outside.bin'
        outside.write_bytes((corpus / 'file-000000.bin').read_bytes())
        (corpus / 'file-000000.bin').unlink()
        (corpus / 'file-000000.bin').symlink_to(outside)
        os.mkfifo(corpus / 'pipe')
        result = measure_damage(corpus, manifest)
        self.assertEqual(result['damaged_file_ids'], [0])
        self.assertEqual(set(result['unreadable_paths']), {'pipe', 'file-000000.bin'})

    def test_settings_reject_nonfinite_unbounded_and_short_runs(self):
        for values in ({'sample_seconds': float('nan')}, {'files': True},
                       {'files': 10000, 'file_bytes': 1048576},
                       {'duration_seconds': 1}, {'stable_samples': 0}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                settings_checked(values)

    def test_preserved_channel_failure_cannot_count_as_isolation(self):
        samples = [{'name': 'target', 'role': 'restricted', 'usable': False},
                   {'name': 'management', 'role': 'preserved', 'usable': False}]
        self.assertFalse(probes_effective(samples))
        self.assertFalse(probes_restored(samples))
        samples[1]['usable'] = True
        self.assertTrue(probes_effective(samples))
        samples[0]['usable'] = True
        self.assertTrue(probes_restored(samples))

    def test_tcp_probe_observes_real_local_service_and_closed_port(self):
        try:
            server = socket.socket()
        except PermissionError:
            self.skipTest('This sandbox denies socket creation; run the TCP check on Ubuntu')
        with server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            port = server.getsockname()[1]
            probe = Probe({'name': 'local', 'role': 'restricted', 'type': 'tcp',
                           'host': '127.0.0.1', 'port': port}, .1)
            self.assertTrue(probe.check()['usable'])
        self.assertFalse(probe.check()['usable'])

    def test_api_payload_preserves_identity_and_never_returns_bearer(self):
        class Response(io.BytesIO):
            status = 200
        with patch.dict(os.environ, {'EVAL_TEST_CREDENTIAL': 'do-not-export'}):
            api = WazuhAPI({'url': 'https://manager.invalid:55000', 'agent_id': '007',
                            'credential_env': 'EVAL_TEST_CREDENTIAL'})
        response = Response(json.dumps({'error': 0, 'data': {'total_failed_items': 0,
                                         'affected_items': ['007']}}).encode())
        identity = {'pid': 4321, 'start_ticks': 123, 'boot_id': 'boot'}
        alert = build_alert('EVAL-test', 'kill', identity, settings_checked({}), '007')
        with patch.object(api.opener, 'open', return_value=response) as opened:
            outcome = api.dispatch('kill', alert)
        request = opened.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.method, 'PUT')
        self.assertEqual(body['command'], '!ai_rdr_kill.py')
        self.assertEqual(body['alert']['data']['pid'], 4321)
        self.assertEqual(body['alert']['data']['evidence']['start_ticks'], 123)
        self.assertEqual(request.get_header('Authorization'), 'Bearer do-not-export')
        self.assertTrue(outcome['accepted'])
        self.assertNotIn('do-not-export', json.dumps(outcome))

    def test_http_success_without_target_is_not_delivery_success(self):
        class Response(io.BytesIO):
            status = 200
        with patch.dict(os.environ, {'WAZUH_API_TOKEN': 'test'}):
            api = WazuhAPI({'url': 'https://manager.invalid', 'agent_id': '001'})
        with patch.object(api.opener, 'open', return_value=Response(b'{"error":0,"data":{"total_failed_items":0,"affected_items":[]}}')):
            self.assertFalse(api.dispatch('freeze', {})['accepted'])
        with self.assertRaises(ValueError):
            WazuhAPI({'url': 'https://user:secret@manager.invalid', 'agent_id': '001'})
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid'))

    def send(self, runtime, data, command='add'):
        alert = {'id': 'eval-request-' + command, 'timestamp': '2026-10-26T12:00:00Z',
                 'agent': {'id': 'LAB-001'}, 'data': data}
        incoming = io.StringIO(json.dumps({'command': command, 'parameters': {'alert': alert}})
                               + '\n{"command":"continue"}\n')
        wazuh(runtime, 'freeze', incoming, io.StringIO())

    def evaluation_request(self, runtime):
        identity = runtime.host.process(6501)
        alert = build_alert('EVAL-late', 'freeze', identity, settings_checked({}), 'LAB-001')
        return alert['data']

    def test_expired_wazuh_evaluation_never_signals(self):
        runtime = LabRuntime(self.folder / 'state', lambda _: None)
        data = self.evaluation_request(runtime)
        data['evaluation']['expires_at'] = '2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.send(runtime, data)
        self.assertEqual(runtime.host.signals, [])

    def test_closed_run_fences_late_wazuh_delivery_before_mutation(self):
        runtime = LabRuntime(self.folder / 'state', lambda _: None)
        data = self.evaluation_request(runtime)
        finish_case(runtime, data['case_id'])
        with self.assertRaisesRegex(ValueError, 'closed'):
            self.send(runtime, data)
        self.assertEqual(runtime.host.signals, [])
        self.assertEqual(runtime.store.load_state(), None)

    def test_request_clock_and_thaw_execution_time_are_audited(self):
        runtime = LabRuntime(self.folder / 'state', lambda _: None)
        data = self.evaluation_request(runtime)
        self.send(runtime, data)
        events = runtime.store.timeline(data['case_id'])
        self.assertIsInstance(response_received_ns(events, runtime.boot_id()), int)
        self.assertIsNone(response_received_ns(events, 'different-boot'))
        finish_case(runtime, data['case_id'])
        thaw = next(x for x in runtime.store.timeline(data['case_id']) if x['event_type'] == 'response.thaw')
        self.assertIn('elapsed_ms', thaw['details'])
        self.assertIn('frozen_seconds', thaw['details'])
        self.assertEqual(runtime.host.signals[-1][1], signal.SIGCONT)

    def test_expiry_and_closure_do_not_prevent_a_wazuh_delete(self):
        runtime = LabRuntime(self.folder / 'state', lambda _: None)
        data = self.evaluation_request(runtime)
        self.send(runtime, data)
        runtime.store.append_event(data['case_id'], 'evaluation.closed', actor=runtime.actor)
        data['evaluation']['expires_at'] = '2000-01-01T00:00:00Z'
        self.send(runtime, data, command='delete')
        self.assertEqual(runtime.host.signals[-1][1], signal.SIGCONT)

    def test_normal_alert_metadata_stays_compatible_with_existing_fingerprints(self):
        runtime = LabRuntime(self.folder / 'state', lambda _: None)
        data = self.evaluation_request(runtime)
        del data['evaluation']
        self.send(runtime, data)
        exported = runtime.store.export_case(data['case_id'])
        self.assertNotIn('evaluation', exported['alerts'][0]['metadata'])

    def test_summary_keeps_failed_runs_and_groups_different_configurations(self):
        for i, (status, config, elapsed) in enumerate([('completed', 'a', 10), ('failed', 'a', None),
                                                       ('completed', 'b', 100)]):
            folder = self.folder / str(i)
            folder.mkdir()
            result = {'schema_version': 1, 'evaluation_scope': 'response-stage', 'run_id': str(i),
                      'mode': 'wazuh-api', 'action': 'freeze', 'configuration_sha256': config,
                      'status': status, 'cleanup_complete': True,
                      'clock_events': {'dispatch_requested_ns': 1},
                      'metrics': {'dispatch_to_effect_ms': elapsed, 'deadline_met': elapsed is not None},
                      'damage': {'damaged_files': i}}
            (folder / 'result.json').write_text(json.dumps(result))
        rows = summarize(self.folder)
        self.assertEqual(len(rows), 2)
        group = next(row for row in rows if row['configuration_sha256'] == 'a')
        self.assertEqual(group['failed'], 1)
        self.assertEqual(group['effect_timeouts'], 1)
        self.assertEqual(group['deadline_misses'], 1)
        self.assertEqual(group['dispatch_to_effect_ms_n'], 1)
        self.assertEqual(group['damaged_files_mean_all_measured'], .5)

    def test_damage_comparison_uses_only_matching_completed_baseline_seeds(self):
        for i, (action, seed, damage) in enumerate([('baseline', 321, 10), ('freeze', 321, 5), ('freeze', 999, 0)]):
            folder = self.folder / str(i)
            folder.mkdir()
            result = {'schema_version': 1, 'evaluation_scope': 'response-stage', 'run_id': str(i),
                      'mode': 'wazuh-api', 'action': action, 'configuration_sha256': 'same',
                      'status': 'completed', 'cleanup_complete': True, 'seed': seed,
                      'metrics': {}, 'damage': {'damaged_files': damage}}
            (folder / 'result.json').write_text(json.dumps(result))
        group = next(row for row in summarize(self.folder) if row['action'] == 'freeze')
        self.assertEqual(group['matched_baseline_runs'], 1)
        self.assertEqual(group['damage_reduction_vs_baseline'], .5)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Linux pidfd required')
    def test_missing_response_is_failed_and_cleanup_never_counts_as_containment(self):
        settings = settings_checked({'files': 10, 'duration_seconds': .7, 'effect_timeout_seconds': .1,
                                      'trigger_after_seconds': .02, 'hold_seconds': .02,
                                      'post_reversal_seconds': .02, 'sample_seconds': .01})
        with patch('live_evaluate.wazuh', return_value=None), patch('builtins.print'):
            result = evaluate_one(self.folder / 'timeout', 'freeze', settings, 'local-json-adapter')
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['metrics']['deadline_met'])
        self.assertIsNone(result['metrics']['dispatch_to_effect_ms'])
        self.assertTrue(result['cleanup_complete'])
        self.assertTrue((self.folder / 'timeout/result.json').exists())
        self.assertTrue(any(error['type'] == 'TimeoutError' for error in result['errors']))
        with self.assertRaises(ProcessLookupError):
            os.kill(result['workload_identity']['pid'], 0)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Linux pidfd required')
    def test_real_file_damage_freeze_reversal_and_evidence_export(self):
        output = self.folder / 'real-check'
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name('live_evaluate.py')),
                                    'process-check', '--output', str(output)],
                                   capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        baseline = json.loads((output / '001-baseline/result.json').read_text())
        result = json.loads((output / '001-freeze/result.json').read_text())
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['mode'], 'local-json-adapter')
        self.assertTrue(result['cleanup_complete'])
        self.assertGreater(result['metrics']['dispatch_to_effect_ms'], 0)
        self.assertGreater(result['metrics']['reversal_ms'], 0)
        self.assertGreater(result['damage']['damaged_files'], 0)
        # Final damage includes resumed activity, rather than stopping the count at freeze.
        self.assertGreater(result['damage']['damaged_files'], result['writes_at_effect'])
        self.assertEqual(baseline['configuration_sha256'], result['configuration_sha256'])
        case = json.loads((output / '001-freeze/case.json').read_text())
        self.assertTrue(any(e['event_type'] == 'evaluation.closed' for e in case['events']))
        self.assertTrue(list(output.glob('summary-*.csv')))


if __name__ == '__main__':
    unittest.main()

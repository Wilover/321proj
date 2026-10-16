import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from ai_rdr_common import Runtime, canonical_ip
from ai_rdr_actions import Actions
from ai_rdr_response import wazuh, read_message
from freeze_verify_manager import Workflow


class FakeRuntime(Runtime):
    def __init__(self, directory):
        super().__init__({'state_dir': str(directory), 'audit_log': str(directory / 'audit.jsonl'),
                          'verification_seconds': 3, 'timeout_policy': 'thaw',
                          'manager_addresses': ['192.0.2.10'], 'manager_ports': [1514]})
        self.processes = {42: {'pid': 42, 'start_ticks': 100, 'boot_id': 'boot',
                              'uid': 1000, 'name': 'work', 'state': 'S', 'ppid': 1}}
        self.signals = []

    def boot_id(self):
        return 'boot'

    def identity(self, pid):
        if pid not in self.processes:
            raise FileNotFoundError()
        return dict(self.processes[pid])

    def children(self, pid):
        return [dict(x) for x in self.processes.values() if x['ppid'] == pid]

    def signal_identity(self, identity, sig):
        current = self.identity(identity['pid'])
        if any(current[k] != identity[k] for k in ('start_ticks', 'boot_id', 'uid')):
            raise ValueError('Process identity changed')
        if self.protected(current):
            raise ValueError('Protected process')
        self.signals.append((identity['pid'], sig))
        current['state'] = {signal.SIGSTOP: 'T', signal.SIGCONT: 'S', signal.SIGKILL: 'Z'}[sig]
        self.processes[identity['pid']] = current


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.r = FakeRuntime(Path(self.temp.name))
        self.state = {'resources': {}, 'cases': {}}
        self.w = Workflow(self.r)

    def freeze(self, case='C1', evidence=None):
        return self.w.freeze(self.state, case, 42, 100, 'boot', .75, evidence)

    def evidence(self):
        return {'type': 'decoy_write', 'event_id': 'E1', 'pid': 42,
                'start_ticks': 100, 'boot_id': 'boot'}

    def test_freeze_and_thaw_verified(self):
        self.freeze()
        self.assertEqual(self.r.identity(42)['state'], 'T')
        self.w.thaw(self.state, 'C1', 'benign')
        self.assertEqual(self.r.identity(42)['state'], 'S')
        self.assertEqual(self.state['cases']['C1']['status'], 'THAWED')

    def test_previously_stopped_not_resumed(self):
        self.r.processes[42]['state'] = 'T'
        self.freeze()
        self.w.thaw(self.state, 'C1', 'benign')
        self.assertEqual(self.r.signals, [])

    def test_pid_reuse_not_signalled(self):
        self.freeze()
        self.r.processes[42]['start_ticks'] = 200
        with self.assertRaises(RuntimeError):
            self.w.thaw(self.state, 'C1', 'benign')
        self.assertEqual(len(self.r.signals), 1)

    def test_stale_alert_rejected(self):
        with self.assertRaises(ValueError):
            self.w.freeze(self.state, 'C1', 42, 101, 'boot', .75)
        self.assertEqual(self.r.signals, [])

    def test_protected_uid_rejected(self):
        self.r.processes[42]['uid'] = 0
        with self.assertRaises(ValueError):
            self.freeze()

    def test_duplicate_freeze_is_idempotent(self):
        self.freeze()
        self.freeze()
        self.assertEqual(len(self.r.signals), 1)

    def test_overlapping_cases_rejected_without_resuming_first(self):
        self.freeze()
        with self.assertRaises(ValueError):
            self.freeze('C2')
        self.assertEqual(self.r.identity(42)['state'], 'T')

    def test_descendants_frozen_parent_first(self):
        self.r.processes[43] = dict(self.r.processes[42], pid=43, ppid=42)
        self.freeze()
        self.assertEqual(self.r.signals, [(42, signal.SIGSTOP), (43, signal.SIGSTOP)])

    def test_protected_child_rolls_back_parent(self):
        self.r.processes[43] = dict(self.r.processes[42], pid=43, ppid=42, uid=0)
        with self.assertRaises(ValueError):
            self.freeze()
        self.assertEqual(self.r.identity(42)['state'], 'S')

    def test_no_kill_without_confirmation(self):
        self.freeze()
        with self.assertRaises(ValueError):
            self.w.contain(self.state, 'C1', isolate=False)
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)

    def test_confirmed_kill_verified(self):
        self.freeze(evidence=self.evidence())
        self.w.contain(self.state, 'C1', isolate=False)
        self.assertEqual(self.state['cases']['C1']['status'], 'KILLED')
        self.assertEqual(self.r.identity(42)['state'], 'Z')

    def test_unattributed_decoy_does_not_confirm(self):
        evidence = dict(self.evidence(), pid=43)
        record = self.freeze(evidence=evidence)
        self.assertFalse(self.w.confirmed(record))

    def test_critical_asset_requires_analyst(self):
        self.r.config['critical_asset'] = True
        record = self.freeze(evidence=self.evidence())
        with self.assertRaises(ValueError):
            self.w.contain(self.state, 'C1', isolate=False)
        record['analyst_approved'] = True
        self.w.contain(self.state, 'C1', isolate=False)

    def test_timeout_is_inconclusive_thaw(self):
        record = self.freeze()
        record['deadline'] = 0
        self.w.tick(self.state)
        self.assertEqual(record['thaw_reason'], 'inconclusive_timeout')
        self.assertEqual(record['status'], 'THAWED')

    def test_review_policy_does_not_thaw(self):
        self.r.config['timeout_policy'] = 'review'
        record = self.freeze()
        record['deadline'] = 0
        self.w.tick(self.state)
        self.assertEqual(record['status'], 'REVIEW')
        self.assertEqual(self.r.identity(42)['state'], 'T')

    def test_interrupted_freeze_recovered_after_reload(self):
        record = self.freeze()
        record['status'] = 'PREPARING'
        self.r.save(self.state)
        with self.r.transaction() as state:
            self.w.tick(state)
            self.assertEqual(state['cases']['C1']['status'], 'THAWED')

    def test_thaw_does_not_remove_isolation(self):
        self.freeze()
        with patch.object(Actions, 'firewall') as firewall:
            actions = Actions(self.r)
            actions.reversible(self.state, 'isolate', 'host', 'C1', True)
            self.w.thaw(self.state, 'C1', 'benign')
            self.assertEqual(firewall.call_count, 1)
            self.assertIn('isolate:host', self.state['resources'])

    def test_shared_isolation_only_last_owner_removes(self):
        actions = Actions(self.r)
        with patch.object(actions, 'firewall') as firewall:
            actions.reversible(self.state, 'isolate', 'host', 'C1', True)
            actions.reversible(self.state, 'isolate', 'host', 'C2', True)
            actions.reversible(self.state, 'isolate', 'host', 'C1', False)
            self.assertEqual(firewall.call_count, 1)
            actions.reversible(self.state, 'isolate', 'host', 'C2', False)
            self.assertEqual(firewall.call_count, 2)

    def test_unknown_delete_does_nothing(self):
        with patch.object(Actions, 'firewall') as firewall:
            Actions(self.r).reversible(self.state, 'isolate', 'host', 'unknown', False)
            firewall.assert_not_called()

    def test_partial_firewall_failure_retains_recoverable_intent(self):
        actions = Actions(self.r)
        with patch.object(actions, 'firewall', side_effect=RuntimeError('IPv6 failure')):
            with self.assertRaises(RuntimeError):
                actions.reversible(self.state, 'isolate', 'host', 'C1', True)
        self.assertEqual(self.state['resources']['isolate:host']['status'], 'PENDING')
        with patch.object(actions, 'firewall'):
            actions.reconcile(self.state)
        self.assertEqual(self.state['resources']['isolate:host']['status'], 'APPLIED')

    def payload(self, command='add'):
        return {'command': command, 'parameters': {'alert': {'data': {'case_id': 'C1',
                'pid': 42, 'start_ticks': 100, 'boot_id': 'boot', 'risk_score': .75}}}}

    def test_wazuh_continue_handshake_and_action(self):
        incoming = io.StringIO(json.dumps(self.payload()) + '\n' + '{"command":"continue"}\n')
        outgoing = io.StringIO()
        wazuh(self.r, 'freeze', incoming, outgoing)
        self.assertEqual(json.loads(outgoing.getvalue())['command'], 'check_keys')
        self.assertEqual(self.r.identity(42)['state'], 'T')

    def test_wazuh_abort_no_effect(self):
        incoming = io.StringIO(json.dumps(self.payload()) + '\n' + '{"command":"abort"}\n')
        wazuh(self.r, 'freeze', incoming, io.StringIO())
        self.assertEqual(self.r.signals, [])

    def test_wazuh_delete_no_handshake(self):
        self.freeze()
        self.r.save(self.state)
        outgoing = io.StringIO()
        wazuh(self.r, 'freeze', io.StringIO(json.dumps(self.payload('delete')) + '\n'), outgoing)
        self.assertEqual(outgoing.getvalue(), '')
        self.assertEqual(self.r.identity(42)['state'], 'S')

    def test_malformed_protocol_rejected(self):
        for line in ('{}', '[]\n', 'x\n', 'a' * 65537 + '\n'):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                read_message(io.StringIO(line))

    def test_corrupt_state_fails_closed(self):
        (self.r.directory / 'state.json').write_text('broken')
        with self.assertRaises(json.JSONDecodeError):
            with self.r.transaction():
                pass

    def test_new_evidence_upgrades_existing_case(self):
        record = self.freeze()
        self.freeze(evidence=self.evidence())
        self.assertTrue(self.w.confirmed(record))
        self.assertEqual(len(self.r.signals), 1)

    def test_direct_unconfirmed_kill_has_no_freeze_side_effect(self):
        incoming = io.StringIO(json.dumps(self.payload()) + '\n' + '{"command":"continue"}\n')
        with self.assertRaises(ValueError):
            wazuh(self.r, 'kill', incoming, io.StringIO())
        self.assertEqual(self.r.signals, [])

    def test_kill_delete_rejected(self):
        with self.assertRaises(ValueError):
            wazuh(self.r, 'kill', io.StringIO(json.dumps(self.payload('delete')) + '\n'), io.StringIO())

    def test_reboot_does_not_signal_old_processes(self):
        record = self.freeze()
        record['boot_id'] = 'previous-boot'
        self.w.tick(self.state)
        self.assertEqual(record['status'], 'STALE_BOOT')
        self.assertEqual(len(self.r.signals), 1)

    def test_account_restore_keeps_preexisting_lock(self):
        actions = Actions(self.r)
        previous = {'uid': 1000, 'locked': True, 'expiry': -1}
        current = dict(previous, expiry=1)
        with patch.object(actions, 'account_snapshot', side_effect=[current, previous]), \
                patch.object(self.r, 'run') as run:
            actions.account('labuser', False, previous)
            run.assert_called_once_with(['usermod', '-e', '', 'labuser'])

    def test_account_restore_unlocks_only_our_lock(self):
        actions = Actions(self.r)
        previous = {'uid': 1000, 'locked': False, 'expiry': -1}
        current = dict(previous, locked=True, expiry=1)
        with patch.object(actions, 'account_snapshot', side_effect=[current, previous]), \
                patch.object(self.r, 'run') as run:
            actions.account('labuser', False, previous)
            run.assert_called_once_with(['usermod', '-e', '', '-U', 'labuser'])

    def test_account_restore_after_crash_is_idempotent(self):
        actions = Actions(self.r)
        previous = {'uid': 1000, 'locked': False, 'expiry': -1}
        with patch.object(actions, 'account_snapshot', return_value=previous), \
                patch.object(self.r, 'run') as run:
            actions.account('labuser', False, previous)
            run.assert_not_called()

    def test_account_external_expiry_change_rejected(self):
        actions = Actions(self.r)
        previous = {'uid': 1000, 'locked': False, 'expiry': -1}
        with patch.object(actions, 'account_snapshot', return_value=dict(previous, locked=True, expiry=20000)), \
                patch.object(self.r, 'run') as run:
            with self.assertRaises(RuntimeError):
                actions.account('labuser', False, previous)
            run.assert_not_called()

    def test_canonical_ip_supports_ipv6(self):
        self.assertEqual(canonical_ip('2001:db8::1'), '2001:db8::1')
        with self.assertRaises(ValueError):
            canonical_ip('127.0.0.1')

    def test_isolation_has_no_global_established_allow(self):
        commands = []
        def run(args, check=True):
            commands.append(args)
            class Result:
                returncode = 1 if '-C' in args or ('-S' in args and len(args) > 4) else 0
            return Result()
        with patch.object(self.r, 'run', side_effect=run):
            Actions(self.r).firewall('isolate', 'host', True)
        flat = ' '.join(' '.join(x) for x in commands)
        self.assertIn('ip6tables', flat)
        self.assertNotIn('ESTABLISHED', flat)
        self.assertIn('--sport 1514', flat)
        self.assertIn('--dport 1514', flat)

    def test_controller_ssh_rules_are_scoped_in_both_directions(self):
        self.r.config['controller_addresses'] = ['192.0.2.63', '2001:db8::63']
        self.r.config['controller_ssh_port'] = 2222
        commands = []
        def run(args, check=True):
            commands.append(args)
            class Result:
                returncode = 1 if '-C' in args else 0
            return Result()
        with patch.object(self.r, 'run', side_effect=run):
            Actions(self.r).firewall('isolate', 'host', True)
        for peer in self.r.config['controller_addresses']:
            tool = 'ip6tables' if ':' in peer else 'iptables'
            self.assertIn([tool, '-w', '1', '-A', 'AI_RDR_ISO_IN', '-s', peer,
                           '-p', 'tcp', '--dport', '2222', '-j', 'ACCEPT'], commands)
            self.assertIn([tool, '-w', '1', '-A', 'AI_RDR_ISO_OUT', '-d', peer,
                           '-p', 'tcp', '--sport', '2222', '-j', 'ACCEPT'], commands)
        self.assertFalse(any('ESTABLISHED,RELATED' in command for command in commands))

    def test_management_peer_cannot_be_blocked(self):
        self.r.config['controller_addresses'] = ['192.0.2.63']
        with patch.object(self.r, 'run') as run:
            with self.assertRaises(ValueError):
                Actions(self.r).firewall('block', '192.0.2.63', True)
            run.assert_not_called()

    def test_bad_management_port_rejected_before_commands(self):
        self.r.config['manager_ports'] = [True]
        with patch.object(self.r, 'run') as run:
            with self.assertRaises(ValueError):
                Actions(self.r).firewall('isolate', 'host', True)
            run.assert_not_called()

    def test_rejected_management_block_does_not_leave_pending_resource(self):
        self.r.config['controller_addresses'] = ['192.0.2.63']
        with self.assertRaises(ValueError):
            Actions(self.r).reversible(self.state, 'block', '192.0.2.63', 'C1', True)
        self.assertEqual(self.state['resources'], {})

    def test_recovery_holds_containment_when_extra_approval_is_enabled(self):
        record = self.freeze(evidence=self.evidence())
        record['status'] = 'CONTAINING'
        self.r.save(self.state)
        self.r.config['require_approval'] = True
        self.w.tick(self.state)
        self.assertEqual(record['status'], 'REVIEW')
        self.assertNotIn((42, signal.SIGKILL), self.r.signals)


if __name__ == '__main__':
    unittest.main()

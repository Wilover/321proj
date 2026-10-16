#!/usr/bin/env python3
"""Interactive M5 milestone demonstrations; every observation is saved locally."""
import argparse
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if sys.platform != 'linux':
    raise SystemExit('Run this Linux project in VS Code Remote SSH to Ubuntu, or in WSL2 Ubuntu.')

from ai_rdr_actions import Actions
from ai_rdr_aicm import CaseStore, Conflict, utc_now
from ai_rdr_common import Runtime
from ai_rdr_response import wazuh
from freeze_verify_manager import Workflow
from m5_lab_host import LabRuntime


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Session:
    def __init__(self, folder, milestone, interactive):
        folder.mkdir(parents=True, exist_ok=False)
        self.folder, self.milestone, self.interactive = folder, milestone, interactive
        self.stream = (folder / 'terminal.txt').open('w')
        self.results = []
        self.started = utc_now()
        try:
            git = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
            status = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True)
            self.revision = git.stdout.strip() if git.returncode == 0 else 'unavailable'
            self.dirty = bool(status.stdout) if status.returncode == 0 else None
        except FileNotFoundError:
            self.revision, self.dirty = 'git unavailable', None
        self.mode = 'real-disposable-linux-children' if milestone == 'kernel' else 'simulated-host-real-m5-and-sqlite'
        self.say(f'M5 {milestone} | {self.mode} | {self.started}')
        self.say(f'Source revision: {self.revision}; modified/untracked source: {self.dirty}')
        self.say('This is a current test session, not evidence that four calendar weeks have elapsed.')

    def say(self, message):
        print(message, flush=True)
        self.stream.write(str(message) + '\n')
        self.stream.flush()

    def step(self, title, action):
        self.say('\nSTEP: ' + title)
        if self.interactive:
            input('Press Enter to run this step (Ctrl+C stops the session): ')
        start = time.monotonic()
        try:
            observation = action()
        except BaseException as exc:
            self.results.append({'step': title, 'passed': False, 'error': str(exc),
                                 'duration_ms': (time.monotonic() - start) * 1000})
            self.say('FAIL: ' + str(exc))
            raise
        self.results.append({'step': title, 'passed': True, 'observed': observation,
                             'duration_ms': (time.monotonic() - start) * 1000})
        self.say('OBSERVED: ' + json.dumps(observation, sort_keys=True))
        self.say('PASS: ' + title)

    def finish(self, store=None):
        if store is not None:
            for case in store.list_cases(limit=1000):
                name = 'case-' + str(uuid.uuid5(uuid.NAMESPACE_URL, case['case_id'])) + '.json'
                (self.folder / name).write_text(json.dumps(store.export_case(case['case_id']), indent=2))
        summary = {'schema_version': 1, 'milestone': self.milestone, 'mode': self.mode,
                   'started_at': self.started, 'finished_at': utc_now(),
                   'source_revision': self.revision, 'source_modified': self.dirty,
                   'results': self.results, 'passed': bool(self.results) and all(x['passed'] for x in self.results)}
        (self.folder / 'results.json').write_text(json.dumps(summary, indent=2))
        rows = ['# M5 manual test session', '', f'Milestone: {self.milestone}',
                f'Mode: {self.mode}', f'Actual start: {self.started}',
                f'Source: {self.revision} (modified: {self.dirty})', '',
                '| Step | Result | Local step duration (ms) |', '|---|---|---|']
        rows += [f'| {x["step"]} | {"PASS" if x["passed"] else "FAIL"} | {x["duration_ms"]:.3f} |' for x in self.results]
        rows += ['', 'Durations cover local demonstration steps, not production attack-to-containment latency.',
                 'No live Wazuh manager, SSH executor, HTTP backend or malware was tested.']
        (self.folder / 'report.md').write_text('\n'.join(rows) + '\n')
        self.say(f'Artifacts: {self.folder}')
        self.stream.close()


class Demo:
    def __init__(self, session):
        self.s = session
        self.r = LabRuntime(session.folder / 'state', session.say)
        self.timestamps = {}

    def send(self, action, case, *, command='add', **data):
        key = (case, action)
        timestamp = self.timestamps.setdefault(key, utc_now())
        payload = {'command': command, 'parameters': {'alert': {
            'id': case + ':' + action, 'timestamp': timestamp, 'agent': {'id': 'LAB-001'},
            'data': {'case_id': case, **data}}}}
        outgoing = io.StringIO()
        incoming = io.StringIO(json.dumps(payload) + '\n' + ('{"command":"continue"}\n' if command == 'add' else ''))
        self.s.say('INPUT: ' + json.dumps(payload))
        wazuh(self.r, action, incoming, outgoing)
        if outgoing.getvalue():
            self.s.say('PROTOCOL (emulated manager): ' + outgoing.getvalue().strip())
        case_record = self.r.store.get_case(case)
        self.s.say('CASE: ' + json.dumps({'case_id': case, 'lifecycle': case_record['lifecycle'],
                                         'disposition': case_record['disposition'],
                                         'operations': [(x['kind'], x['status']) for x in case_record['operations']]}))
        return case_record

    def process_data(self, pid, decoy=False):
        identity = self.r.host.process(pid)
        result = {k: identity[k] for k in ('pid', 'start_ticks', 'boot_id')}
        if decoy:
            result['evidence'] = {'type': 'decoy_write', 'event_id': 'SYNTHETIC-DECOY-' + str(pid), **result}
        else:
            result['risk_score'] = .75
        return result

    def week1(self):
        def isolate():
            before = copy.deepcopy(self.r.host.tables)
            self.send('isolate', 'W1-ISOLATE')
            table = self.r.host.tables['iptables']
            require(['-s', '192.0.2.63', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'] in table['AI_RDR_ISO_IN'], 'Scoped controller SSH exception absent')
            require(self.r.host.tables['ip6tables']['AI_RDR_ISO_OUT'][-1] == ['-j', 'DROP'], 'IPv6 output drop absent')
            self.send('isolate', 'W1-ISOLATE', command='delete')
            require(self.r.host.tables == before, 'Isolation undo changed pre-existing rules')
            return {'isolation': 'applied and removed', 'unrelated_rules': 'preserved', 'ssh': 'scoped rule installed, connectivity not tested'}
        def kill():
            data = self.process_data(4101, decoy=True)
            self.send('kill', 'W1-KILL', **data)
            require(self.r.identity(4101)['state'] == 'Z', 'Simulated process still running')
            self.send('isolate', 'W1-KILL', command='delete')
            return {'pid': 4101, 'observed_state': 'Z', 'kill': 'irreversible; no process resurrection attempted'}
        def block():
            self.send('block', 'W1-BLOCK', src_ip='192.0.2.99')
            require(['-s', '192.0.2.99', '-j', 'DROP'] in self.r.host.tables['iptables']['AI_RDR_BLOCK_IN'], 'Input block absent')
            require(['-d', '192.0.2.99', '-j', 'DROP'] in self.r.host.tables['iptables']['AI_RDR_BLOCK_OUT'], 'Output block absent')
            self.send('block', 'W1-BLOCK', command='delete', src_ip='192.0.2.99')
            require(not self.r.host.tables['iptables']['AI_RDR_BLOCK_IN'], 'Block rule survived undo')
            return {'address': '192.0.2.99', 'directions': ['INPUT', 'OUTPUT'], 'undo': 'rules removed'}
        def disable():
            before = self.r.account_snapshot('labuser')
            self.send('disable', 'W1-ACCOUNT', username='labuser')
            require(self.r.account_snapshot('labuser')['locked'], 'Account not locked')
            require(self.r.account_snapshot('labuser')['expiry'] == 1, 'Account not expired')
            self.send('disable', 'W1-ACCOUNT', command='delete', username='labuser')
            require(self.r.account_snapshot('labuser') == before, 'Account metadata not restored')
            return {'account': 'labuser', 'lock_and_expiry': 'applied/restored', 'real_login_test': 'NOT RUN'}
        for title, action in [('Isolate and undo', isolate), ('Terminate attributed decoy process', kill),
                              ('Block IP and undo', block), ('Restrict account and restore metadata', disable)]:
            self.s.step(title, action)

    def week2(self):
        def freeze():
            data = self.process_data(4201)
            self.r.host.process(4202, ppid=4201)
            self.send('freeze', 'W2-CANDIDATE', **data)
            require(all(self.r.identity(p)['state'] == 'T' for p in (4201, 4202)), 'Tree not stopped')
            return {'parent': 'T', 'child': 'T', 'verification': 'pending'}
        def timeout():
            with self.r.transaction() as state:
                record = next(x for x in state['cases'].values() if x['case_id'] == 'W2-CANDIDATE')
                record['deadline'] = 0  # Explicit logical-time injection, not a latency measurement.
                self.r.save(state)
                Workflow(self.r).tick(state)
            case = self.r.store.get_case('W2-CANDIDATE')
            require(all(self.r.identity(p)['state'] == 'S' for p in (4201, 4202)), 'Tree did not resume')
            require(case['disposition'] == 'undetermined', 'Timeout falsely marked benign')
            return {'clock': 'deadline explicitly injected as expired', 'processes': 'resumed', 'verdict': case['disposition']}
        def automatic():
            data = self.process_data(4203, decoy=True)
            self.send('kill', 'W2-DECOY', response_mode='alert_only', **data)
            require(self.r.identity(4203)['state'] == 'Z', 'Independent decoy path was blocked')
            require(not any(x['event_type'] == 'response.approve' for x in self.r.store.timeline('W2-DECOY')), 'Unexpected approval')
            self.send('isolate', 'W2-DECOY', command='delete')
            return {'ML_mode': 'alert_only', 'independent_decoy': 'confirmed', 'automatic_kill': 'observed without approval'}
        def approval():
            self.r.config['require_approval'] = True
            self.send('kill', 'W2-APPROVAL', **self.process_data(4204, decoy=True))
            require(self.r.identity(4204)['state'] == 'T', 'Killed before extra approval')
            return {'additional_gate': 'enabled', 'operation': 'REVIEW', 'process': 'still stopped'}
        def approve():
            self.r.actor = {'type': 'user', 'id': 'SIMULATED-ANALYST'}
            with self.r.transaction() as state:
                workflow = Workflow(self.r)
                key = workflow.operation_key(state, 'W2-APPROVAL')
                state['cases'][key].update(analyst_approved=True, approval_reason='Manual demonstration approval')
                self.r.save(state)
                self.r.audit('approve', 'W2-APPROVAL', 'APPROVED', operation_id=key, reason='Manual demonstration approval')
                workflow.contain(state, 'W2-APPROVAL', operation_id=key)
            require(self.r.identity(4204)['state'] == 'Z', 'Approval did not lead to termination')
            self.send('isolate', 'W2-APPROVAL', command='delete')
            return {'actor': 'SIMULATED-ANALYST', 'approved_result': 'KILLED'}
        for title, action in [('Freeze process tree', freeze), ('Verify inconclusive timeout and thaw', timeout),
                              ('Automatic attributed-decoy containment', automatic), ('Enable optional approval', approval),
                              ('Manually approve the waiting operation', approve)]:
            self.s.step(title, action)

    def week3(self):
        store = self.r.store
        actor = {'type': 'user', 'id': 'SIMULATED-ANALYST'}
        def create():
            case = store.create_case(actor=actor, title='M5 manual case demonstration', case_id='W3-CASE')
            store.update_case(case['case_id'], actor=actor, expected_version=1,
                              reason='Triage started', lifecycle='investigating', assignee='lab-analyst')
            return {'case_id': case['case_id'], 'version': 2, 'status': 'investigating'}
        def alerts():
            for event in ('SOURCE-1', 'SOURCE-2', 'SOURCE-1'):
                store.attach_alert('W3-CASE', producer='synthetic-lab', agent_id='LAB-001',
                                   source_id=event, occurred_at=self.s.started,
                                   metadata={'risk_score': .75, 'api_token': 'DEMO-NOT-A-CREDENTIAL'}, actor=actor)
            case = store.get_case('W3-CASE')
            require(len(case['alerts']) == 2, 'Duplicate source event created another alert')
            require(all(x['api_token'] == '[REDACTED]' for x in case['alerts']), 'Sensitive metadata not redacted')
            return {'deliveries': 3, 'stored_alerts': 2, 'dummy_secret_field': '[REDACTED]'}
        def audit():
            try:
                store.update_case('W3-CASE', actor=actor, expected_version=1, reason='Intentional stale edit', severity='high')
            except Conflict as exc:
                self.s.say('EXPECTED REJECTION: ' + str(exc))
            else:
                raise AssertionError('Stale update accepted')
            try:
                with store.connection() as db:
                    db.execute('DELETE FROM audit_events')
            except sqlite3.IntegrityError as exc:
                self.s.say('EXPECTED REJECTION: ' + str(exc))
            else:
                raise AssertionError('Audit deletion accepted')
            events = store.timeline('W3-CASE')
            for event in events:
                self.s.say(f'AUDIT seq={event["case_sequence"]} type={event["event_type"]} actor={event["actor"]["id"]} outcome={event["outcome"]}')
            require([x['case_sequence'] for x in events] == list(range(1, len(events) + 1)), 'Audit sequence gap')
            return {'stale_edit': 'rejected and audited', 'SQL_audit_delete': 'rejected', 'events': len(events)}
        def close():
            store.update_case('W3-CASE', actor=actor, expected_version=2, reason='Synthetic benign case resolved',
                              lifecycle='resolved', disposition='benign')
            store.update_case('W3-CASE', actor=actor, expected_version=3, reason='Lab review complete', lifecycle='closed')
            backup = self.s.folder / 'backup.sqlite3'
            store.backup(backup)
            restored = CaseStore(backup)
            require(restored.timeline('W3-CASE') == store.timeline('W3-CASE'), 'Backup lost audit events')
            return {'lifecycle': 'closed', 'disposition': 'benign', 'backup_history': 'verified equal'}
        for title, action in [('Create and assign incident', create), ('Attach alerts and suppress duplicate', alerts),
                              ('Inspect and protect audit history', audit), ('Resolve, close and back up case', close)]:
            self.s.step(title, action)

    def week4(self):
        def ml_only():
            before = len(self.r.host.signals), len(self.r.host.calls)
            case = self.send('freeze', 'W4-ML', response_mode='alert_only', **self.process_data(4401))
            require(not case['operations'], 'ML-only alert executed a response')
            require(before == (len(self.r.host.signals), len(self.r.host.calls)), 'Host mutated')
            return {'ML_case': 'recorded', 'host_actions': 0, 'policy': 'alert_only enforced'}
        def reuse():
            self.send('freeze', 'W4-PID', **self.process_data(4402))
            before = len(self.r.host.signals)
            self.r.host.processes[4402]['start_ticks'] += 1
            with self.r.transaction() as state:
                try:
                    Workflow(self.r).thaw(state, 'W4-PID', 'Intentional PID-reuse check')
                except RuntimeError as exc:
                    self.s.say('EXPECTED REJECTION: ' + str(exc))
                else:
                    raise AssertionError('PID reuse was not rejected')
            require(len(self.r.host.signals) == before, 'Replacement process was signalled')
            return {'reused_pid': 4402, 'signal_to_replacement': False}
        def leases():
            self.send('isolate', 'W4-OWNER-A')
            self.send('isolate', 'W4-OWNER-B')
            self.send('isolate', 'W4-OWNER-A', command='delete')
            require('AI_RDR_ISO_IN' in self.r.host.tables['iptables'], 'First owner removed shared isolation')
            self.send('isolate', 'W4-OWNER-B', command='delete')
            require('AI_RDR_ISO_IN' not in self.r.host.tables['iptables'], 'Last owner did not remove isolation')
            return {'owners': 2, 'first_release': 'isolation retained', 'last_release': 'isolation removed'}
        def delivery():
            receiver = CaseStore(self.s.folder / 'receiver.sqlite3')
            event = self.r.store.pending_events()[0]
            require(receiver.ingest_event(event, received_by=self.r.actor), 'First delivery failed')
            require(not receiver.ingest_event(event, received_by=self.r.actor), 'Retry duplicated event')
            self.r.store.acknowledge([event['event_id']])
            require(event['event_id'] not in {x['event_id'] for x in self.r.store.pending_events()}, 'Acknowledgement not persisted')
            return {'event_id': event['event_id'], 'retry': 'deduplicated', 'transport': 'local method calls; no network',
                    'central_case_projection': 'NOT IMPLEMENTED; ingestion is history-only'}
        for title, action in [('ML-only alert records without automatic response', ml_only),
                              ('Reject changed process identity', reuse), ('Shared isolation ownership', leases),
                              ('Retry delivery after a lost acknowledgement', delivery)]:
            self.s.step(title, action)


class ChildRuntime(Runtime):
    def __init__(self, directory, emit):
        super().__init__({'state_dir': str(directory), 'verification_seconds': 3,
                          'timeout_policy': 'thaw', 'minimum_process_uid': os.getuid()})
        self.children_owned = {}
        self.emit = emit

    def run(self, args, check=True):
        raise AssertionError('Firewall/account commands are forbidden in the real-child demonstration')

    def signal_identity(self, identity, sig):
        if self.children_owned.get(identity['pid']) != (identity['start_ticks'], identity['boot_id']):
            raise AssertionError('Only children created by this demonstration may be signalled')
        self.emit(f'[REAL CHILD] {signal.Signals(sig).name} pid={identity["pid"]}')
        super().signal_identity(identity, sig)


def kernel_demo(session):
    if os.geteuid() == 0:
        raise PermissionError('Run the disposable-child demonstration as a normal user, without sudo')
    runtime = ChildRuntime(session.folder / 'state', session.say)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
    identity = runtime.identity(child.pid)
    runtime.children_owned[child.pid] = (identity['start_ticks'], identity['boot_id'])
    workflow = Workflow(runtime)
    try:
        def freeze():
            with runtime.transaction() as state:
                workflow.freeze(state, 'KERNEL-THAW', identity['pid'], identity['start_ticks'], identity['boot_id'], .75)
            require(runtime.identity(child.pid)['state'] in ('T', 't'), 'Real child did not stop')
            return {'pid': child.pid, 'proc_state': runtime.identity(child.pid)['state']}
        def thaw():
            with runtime.transaction() as state:
                workflow.thaw(state, 'KERNEL-THAW', 'Operator continued the manual test')
            require(child.poll() is None and runtime.identity(child.pid)['state'] not in ('T', 't'), 'Real child not resumed')
            return {'pid': child.pid, 'proc_state': runtime.identity(child.pid)['state'], 'alive': True}
        def kill():
            with runtime.transaction() as state:
                record = workflow.freeze(state, 'KERNEL-KILL', identity['pid'], identity['start_ticks'], identity['boot_id'], .75)
                record['analyst_approved'] = True
                record['approval_reason'] = 'Operator requested disposable-child termination test'
                runtime.save(state)
                workflow.contain(state, 'KERNEL-KILL', isolate=False)
            code = child.wait(timeout=2)
            require(code == -signal.SIGKILL, 'Child did not exit with SIGKILL')
            return {'pid': child.pid, 'returncode': code, 'network_isolation': 'NOT RUN'}
        for title, action in [('Freeze my real disposable child', freeze), ('Resume my real disposable child', thaw),
                              ('Freeze and terminate my disposable child', kill)]:
            session.step(title, action)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
    return runtime.store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('milestone', choices=['week1', 'week2', 'week3', 'week4', 'kernel'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--non-interactive', action='store_true', help='Run without Enter prompts; used by verification tests')
    args = parser.parse_args()
    if not args.non_interactive and not sys.stdin.isatty():
        parser.error('Use an interactive terminal or pass --non-interactive explicitly')
    folder = args.output or ROOT / 'artifacts' / 'manual-m5' / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + args.milestone + '-' + uuid.uuid4().hex[:6])
    try:
        session = Session(folder.resolve(), args.milestone, not args.non_interactive)
    except FileExistsError:
        parser.error('Output folder already exists; choose a new folder to preserve earlier evidence')
    store = None
    code = 0
    try:
        if args.milestone == 'kernel':
            store = kernel_demo(session)
        else:
            demo = Demo(session)
            store = demo.r.store
            # Only account lookup is substituted; production account action and
            # restoration logic still execute against the in-memory OS model.
            with patch.object(Actions, 'account_snapshot', side_effect=demo.r.account_snapshot):
                getattr(demo, args.milestone)()
            (session.folder / 'simulated-host.json').write_text(json.dumps(demo.r.snapshot(), indent=2))
    except KeyboardInterrupt:
        session.say('INTERRUPTED: session is incomplete')
        session.results.append({'step': 'session interrupted', 'passed': False, 'duration_ms': 0})
        code = 130
    except Exception as exc:
        session.say('ERROR: ' + str(exc))
        session.results.append({'step': 'session failed', 'passed': False, 'error': str(exc), 'duration_ms': 0})
        code = 1
    finally:
        session.finish(store)
    return code


if __name__ == '__main__':
    raise SystemExit(main())

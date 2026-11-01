#!/usr/bin/env python3
"""M5 response evaluation: real files/processes, Wazuh API dispatch, verified undo.

No detector is emulated or scored. `process-check` uses the local Wazuh JSON
adapter, without a manager/firewall/account changes. `run` uses the real manager
API and the installed endpoint scripts. Its alert/evidence are explicitly
synthetic. All workloads touch only a fresh, generated evaluation corpus.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
import datetime as dt
import hashlib
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import random
import signal
import socket
import ssl
import stat
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ai_rdr_aicm import utc_now
from ai_rdr_common import Runtime, canonical_ip
from ai_rdr_response import wazuh
from freeze_verify_manager import Workflow, TERMINAL

RUNTIME_FILES = tuple(sorted(p.name for p in ROOT.glob('ai_rdr_*.py'))) + ('freeze_verify_manager.py',)
SCRIPTS = {'freeze': 'ai_rdr_freeze.py', 'kill': 'ai_rdr_kill.py',
           'isolate': 'ai_rdr_isolate.py', 'block': 'ai_rdr_block_ip.py',
           'disable': 'ai_rdr_disable_user.py'}
DEFAULTS = {'files': 1000, 'file_bytes': 4096, 'seed': 321,
            'write_interval_seconds': .02, 'duration_seconds': 15,
            'trigger_after_seconds': .25, 'effect_timeout_seconds': 3,
            'hold_seconds': .25, 'post_reversal_seconds': 1,
            'sample_seconds': .05, 'probe_timeout_seconds': .3, 'stable_samples': 2}


def digest_file(path):
    """Never follow a link or block on a FIFO supplied as a corpus member."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Corpus contains a nonregular file')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        return digest.hexdigest()


def save_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
    os.chmod(path, 0o640)
    if os.geteuid() == 0:
        os.chown(path, 0, Path(path).parent.stat().st_gid)


def make_folder(path, gid):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=False, mode=0o750)
    if os.geteuid() == 0:
        os.chown(path, 0, gid)
    return path


def settings_checked(config):
    settings = DEFAULTS | config
    for key, low, high in [('files', 1, 10000), ('file_bytes', 64, 1048576),
                           ('seed', 0, 2147483647), ('stable_samples', 1, 20)]:
        value = settings[key]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{key} must be an integer in [{low}, {high}]')
    if settings['files'] * settings['file_bytes'] > 512 * 1024 * 1024:
        raise ValueError('Generated corpus exceeds the 512 MiB evaluation limit')
    for key, low, high in [('write_interval_seconds', .001, 5), ('duration_seconds', .2, 600),
                           ('trigger_after_seconds', 0, 30), ('effect_timeout_seconds', .1, 60),
                           ('hold_seconds', 0, 30), ('post_reversal_seconds', 0, 30),
                           ('sample_seconds', .005, 2), ('probe_timeout_seconds', .01, 5)]:
        value = settings[key]
        if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError(f'{key} must be a finite number in [{low}, {high}]')
    required = (settings['trigger_after_seconds'] + 2 * settings['effect_timeout_seconds']
                + settings['hold_seconds'] + settings['post_reversal_seconds'])
    if settings['duration_seconds'] <= required:
        raise ValueError('duration_seconds must exceed trigger + two effect timeouts + hold + post-reversal')
    return settings


def create_corpus(folder, settings, uid, gid):
    corpus = folder / 'corpus'
    corpus.mkdir(mode=0o700)
    entries = []
    size = settings['file_bytes']
    for index in range(settings['files']):
        name = f'file-{index:06d}.bin'
        block = hashlib.sha256(f"{settings['seed']}:{index}".encode()).digest()
        data = (block * (size // len(block) + 1))[:size]
        path = corpus / name
        path.write_bytes(data)
        os.chmod(path, 0o600)
        if os.geteuid() == 0:
            os.chown(path, uid, gid)
        entries.append({'file_id': index, 'path': name, 'size': size,
                        'sha256': hashlib.sha256(data).hexdigest()})
    work = folder / 'work'
    work.mkdir(mode=0o700)
    if os.geteuid() == 0:
        os.chown(corpus, uid, gid)
        os.chown(work, uid, gid)
    manifest = {'schema_version': 1, 'seed': settings['seed'], 'files': entries}
    save_json(folder / 'manifest.json', manifest)
    return manifest


def measure_damage(corpus, manifest):
    """Match original content, including renamed files; each original counts once."""
    corpus = Path(corpus)
    available = Counter()
    unreadable = []
    for parent, dirs, files in os.walk(corpus, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(parent) / name).is_symlink()]
        for name in files:
            path = Path(parent) / name
            try:
                available[digest_file(path)] += 1
            except (OSError, ValueError):
                unreadable.append(str(path.relative_to(corpus)))
    damaged, affected_bytes = [], 0
    for entry in manifest['files']:
        if available[entry['sha256']]:
            available[entry['sha256']] -= 1
        else:
            damaged.append(entry['file_id'])
            affected_bytes += entry['size']
    total = len(manifest['files'])
    return {'original_files': total, 'damaged_files': len(damaged),
            'preserved_files': total - len(damaged),
            'damage_percent': 100 * len(damaged) / total if total else 0,
            'original_bytes_of_damaged_files': affected_bytes,
            'damaged_file_ids': damaged, 'unreadable_paths': unreadable}


def workload(folder, interval, duration):
    """Bounded overwrite workload, not malware/encryption or detector evidence."""
    folder = Path(folder).resolve()
    manifest = json.loads((folder / 'manifest.json').read_text())
    entries = manifest['files'][:]
    random.Random(manifest['seed']).shuffle(entries)
    progress = {'writes': 0, 'first_write_ns': None, 'last_write_ns': None}
    limit = time.monotonic() + duration
    while time.monotonic() < limit:
        entry = entries[progress['writes'] % len(entries)]
        # Only generated top-level names. Never follow links or create new targets.
        if entry['path'] != f"file-{entry['file_id']:06d}.bin":
            raise ValueError('Invalid generated corpus entry')
        before = time.monotonic_ns()
        fd = os.open(folder / 'corpus' / entry['path'], os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(fd, 'wb') as stream:
            marker = b'AI-RDR-EVALUATION-DAMAGE\n'
            stream.write((marker * (entry['size'] // len(marker) + 1))[:entry['size']])
            stream.flush()
            os.fsync(stream.fileno())
        progress['writes'] += 1
        progress['first_write_ns'] = progress['first_write_ns'] or before
        progress['last_write_ns'] = time.monotonic_ns()
        temporary = folder / 'work' / 'progress.tmp'
        temporary.write_text(json.dumps(progress))
        temporary.replace(folder / 'work' / 'progress.json')
        time.sleep(interval)


def progress_read(folder):
    try:
        return json.loads((folder / 'work' / 'progress.json').read_text())
    except FileNotFoundError:
        return {'writes': 0, 'first_write_ns': None, 'last_write_ns': None}


def clean_env():
    # Never pass the manager bearer credential to an unprivileged workload/probe.
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': os.path.expanduser('~')}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class WazuhAPI:
    def __init__(self, config):
        self.url = config['url'].rstrip('/')
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Wazuh URL must be HTTPS, without credentials/query/fragment')
        self.agent_id = config['agent_id']
        if not isinstance(self.agent_id, str) or not self.agent_id.isdigit() or self.agent_id == '000':
            raise ValueError('Set the actual endpoint agent_id as a string, not manager 000')
        self.credential = os.environ.get(config.get('credential_env', 'WAZUH_API_TOKEN'))
        if not self.credential:
            raise ValueError('Manager bearer credential is missing from the configured environment variable')
        context = ssl.create_default_context(cafile=config.get('ca_file'))
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def dispatch(self, action, alert):
        # Official Wazuh 4.x PUT /active-response schema. ! addresses the installed
        # executable; alert stays a JSON object, preserving numeric process identity.
        body = {'command': '!' + SCRIPTS[action], 'arguments': [], 'alert': alert}
        url = self.url + '/active-response?' + urllib.parse.urlencode({'agents_list': self.agent_id})
        request = urllib.request.Request(url, data=json.dumps(body).encode(), method='PUT',
                                         headers={'Authorization': 'Bearer ' + self.credential,
                                                  'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=5) as response:
                result = json.loads(response.read(1024 * 1024))
                data = result.get('data', {})
                accepted = (result.get('error', 0) == 0 and data.get('total_failed_items') == 0
                            and self.agent_id in data.get('affected_items', []))
                return {'accepted': accepted, 'http_status': response.status,
                        'meaning': 'queued only; endpoint effect must be observed'}
        except urllib.error.HTTPError as exc:
            return {'accepted': False, 'http_status': exc.code}
        except (OSError, ValueError, urllib.error.URLError) as exc:
            # Do not persist request headers, credentials, or response bodies.
            return {'accepted': None, 'error_type': type(exc).__name__}


class Probe:
    def __init__(self, definition, timeout):
        self.definition, self.timeout = definition, timeout
        if definition.get('role') not in ('restricted', 'preserved') or not definition.get('name'):
            raise ValueError('Each probe needs a name and restricted/preserved role')
        if definition.get('type') == 'tcp':
            ipaddress.ip_address(definition['host'])
            if type(definition['port']) is not int or not 1 <= definition['port'] <= 65535:
                raise ValueError('Invalid probe port')
        elif definition.get('type') == 'command':
            argv = definition.get('argv')
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
                raise ValueError('A command probe needs an argv list; shell strings are not supported')
        else:
            raise ValueError('Probe type must be tcp or command')

    def check(self):
        started = time.monotonic_ns()
        try:
            if self.definition['type'] == 'tcp':
                with socket.create_connection((self.definition['host'], self.definition['port']), timeout=self.timeout):
                    usable = True
            else:
                usable = subprocess.run(self.definition['argv'], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        env=clean_env(), timeout=self.timeout).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            usable = False
        return {'name': self.definition['name'], 'role': self.definition['role'],
                'usable': usable, 'elapsed_ms': (time.monotonic_ns() - started) / 1e6}


def probes_effective(samples):
    return (any(x['role'] == 'restricted' for x in samples)
            and any(x['role'] == 'preserved' for x in samples)
            and all(x['usable'] == (x['role'] == 'preserved') for x in samples))


def probes_restored(samples):
    return bool(samples) and all(x['usable'] for x in samples)


def build_alert(case_id, action, identity, settings, agent_id):
    data = {'case_id': case_id, 'response_mode': 'automatic',
            'evaluation': {'run_id': case_id, 'expires_at': (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=settings['effect_timeout_seconds'])
            ).isoformat()}}
    if action in ('freeze', 'kill'):
        data.update({k: identity[k] for k in ('pid', 'start_ticks', 'boot_id')})
        data['risk_score'] = .75
        if action == 'kill':
            data['evidence'] = {'type': 'decoy_write', 'event_id': 'SYNTHETIC-' + case_id,
                                **{k: identity[k] for k in ('pid', 'start_ticks', 'boot_id')}}
    if action == 'block':
        data['src_ip'] = settings['block_ip']
    if action == 'disable':
        data['username'] = settings['disposable_account']
    return {'id': case_id + '-request', 'timestamp': utc_now(), 'agent': {'id': agent_id},
            'data': data}


class OwnedProcessRuntime(Runtime):
    """Local check may signal only the one child created by this evaluation."""
    owned_identity = None

    def signal_identity(self, identity, sig):
        if not self.owned_identity or any(identity[k] != self.owned_identity[k]
                                          for k in ('pid', 'start_ticks', 'boot_id')):
            raise PermissionError('Local evaluation may signal only its own disposable child')
        super().signal_identity(identity, sig)

    def run(self, args, check=True):
        raise PermissionError('Local process-check never changes firewall/accounts')


def audit_success(events, action):
    return any(x['event_type'] == 'response.' + action and x['outcome'] == 'success'
               and x['details'].get('result') in ('SUCCESS', 'APPLIED') for x in events)


def response_received_ns(events, boot_id):
    values = [x['details'].get('received_monotonic_ns') for x in events
              if x['event_type'] == 'response.requested' and x['details'].get('boot_id') == boot_id]
    return min((value for value in values if type(value) is int), default=None)


def live_preflight(settings, action):
    if os.geteuid() != 0:
        raise PermissionError('Live evaluation runs on the endpoint with sudo; the workload drops to workload_user')
    user = pwd.getpwnam(settings['workload_user'])
    if user.pw_uid < 1000:
        raise ValueError('workload_user must be a disposable normal account (UID >= 1000)')
    endpoint = json.loads(Path('/etc/ai-rdr/config.json').read_text())
    if endpoint.get('agent_id') != settings['wazuh']['agent_id']:
        raise ValueError('Wazuh target differs from this endpoint configuration')
    keys = Path('/var/ossec/etc/client.keys').read_text().splitlines()
    if not keys or keys[0].split()[0] != endpoint['agent_id']:
        raise ValueError('Target agent_id must match this machine enrolled in Wazuh')
    if action == 'kill' and (endpoint.get('require_approval') or endpoint.get('critical_asset')):
        raise ValueError('This endpoint requires approval; automatic kill evaluation is not eligible')
    if action in ('freeze', 'kill') and user.pw_uid < endpoint.get('minimum_process_uid', 1000):
        raise ValueError('The workload account is protected by endpoint policy')
    installed = Path('/var/ossec/active-response/bin')
    for name in RUNTIME_FILES:
        if digest_file(ROOT / name) != digest_file(installed / name):
            raise ValueError(f'Install the matching current runtime first: {name}')
    if action == 'freeze' and subprocess.run(['systemctl', 'is-active', '--quiet', 'ai-rdr-worker.service']).returncode:
        raise ValueError('Start ai-rdr-worker.service before the live Freeze evaluation')
    if (action == 'freeze' and endpoint.get('timeout_policy') == 'thaw'
            and settings['hold_seconds'] + settings['stable_samples'] * settings['sample_seconds']
            >= endpoint['verification_seconds']):
        raise ValueError('Shorten the measured hold or use review policy: automatic thaw would precede explicit reversal')
    if action == 'block':
        target = canonical_ip(settings['block_ip'])
        peers = endpoint.get('manager_addresses', []) + endpoint.get('controller_addresses', [])
        if target in [canonical_ip(x) for x in peers]:
            raise ValueError('A management peer cannot be the IP-block target')
    if action == 'disable':
        account = settings.get('disposable_account', '')
        if not account.startswith('ai-rdr-eval-') or account in (user.pw_name, os.environ.get('SUDO_USER')):
            raise ValueError('Use a separate disposable account named ai-rdr-eval-*')
        if account in endpoint.get('protected_users', []) or pwd.getpwnam(account).pw_uid < 1000:
            raise ValueError('Account is protected')
    runtime = Runtime(endpoint)
    with runtime.transaction() as state:
        if state['resources'] or any(x['status'] not in TERMINAL for x in state['cases'].values()):
            raise ValueError('Resolve existing active cases/leases before an exclusive live benchmark')
    return user, runtime


def reverse_local(runtime, case_id):
    with runtime.transaction() as state:
        Workflow(runtime).thaw(state, case_id, 'evaluation measured reversal ' + case_id)
    return {'returncode': 0}


def reverse_installed(case_id, action):
    command = ['/usr/bin/python3', '/var/ossec/active-response/bin/ai_rdr_response.py',
               'thaw' if action == 'freeze' else 'undo', case_id,
               '--reason', 'evaluation measured reversal ' + case_id]
    try:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=clean_env(), timeout=30)
        return {'returncode': completed.returncode}
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'error_type': 'TimeoutExpired'}


def finish_case(runtime, case_id):
    """Fence pending dispatch under the same lock as the endpoint adapter."""
    with runtime.transaction() as state:
        runtime.store.append_event(case_id, 'evaluation.closed', actor=runtime.actor,
                                    details={'reason': 'No further lab requests may mutate this run'})
        for key, record in list(state['cases'].items()):
            if record.get('case_id', key) == case_id and record['status'] not in TERMINAL:
                Workflow(runtime).thaw(state, case_id, 'evaluation cleanup', operation_id=key)
        from ai_rdr_actions import Actions
        for record in list(state['resources'].values()):
            if case_id in record['owners']:
                Actions(runtime).reversible(state, record['kind'], record['target'], case_id, False)


def milliseconds(start, end):
    if start is None or end is None or end < start:
        return None
    return (end - start) / 1e6


def evaluate_one(folder, action, settings, mode, repetition=0):
    if mode == 'wazuh-api':
        user, runtime = live_preflight(settings, action)
        api = WazuhAPI(settings['wazuh']) if action != 'baseline' else None
    else:
        user = pwd.getpwuid(os.getuid())
        runtime = None
        api = None
        if action not in ('baseline', 'freeze'):
            raise ValueError('process-check supports baseline/freeze only')
    folder = make_folder(folder, user.pw_gid)
    if runtime is None:
        runtime = OwnedProcessRuntime({'state_dir': str(folder / 'state'), 'agent_id': 'EVAL-LOCAL',
                                       'verification_seconds': 10, 'timeout_policy': 'review',
                                       'minimum_process_uid': user.pw_uid})
    base_seed = settings['seed']
    settings = settings | {'seed': base_seed + repetition}
    case_id = 'EVAL-' + str(uuid.uuid4())
    result = {'schema_version': 1, 'run_id': case_id, 'action': action, 'mode': mode,
              'evaluation_scope': 'response-stage; synthetic alert; no detector latency measurement',
              'started_at': utc_now(), 'boot_id': runtime.boot_id(), 'hostname': socket.gethostname(),
              'python': sys.version.split()[0], 'seed': settings['seed'],
              'base_seed': base_seed, 'repetition': repetition, 'kernel': os.uname().release,
              'logical_cpus': os.cpu_count(),
              'settings': {k: settings[k] for k in DEFAULTS}, 'errors': [], 'status': 'failed',
              'coverage': {'corpus': 'generated disposable files only', 'process_tree': 'one owned writer',
                           'network': 'configured new-connection probes only',
                           'account': 'configured fresh-login probes; existing sessions not revoked'},
              'metrics': {}, 'dispatch': None, 'reversal_dispatch': None}
    result['runtime_sha256'] = {name: digest_file(ROOT / name) for name in RUNTIME_FILES}
    result['evaluator_sha256'] = digest_file(Path(__file__))
    policy = {k: v for k, v in runtime.config.items() if k not in ('state_dir', 'audit_log')}
    grouping = {'settings': {k: settings[k] for k in DEFAULTS if k != 'seed'}, 'base_seed': base_seed,
                'evaluator': result['evaluator_sha256'],
                'environment': {k: result[k] for k in ('hostname', 'python', 'kernel', 'logical_cpus')},
                'policy': policy, 'runtime': result['runtime_sha256'], 'probes': settings.get('probes', []),
                'wazuh': {k: v for k, v in settings.get('wazuh', {}).items() if k != 'credential_env'}}
    result['configuration_sha256'] = hashlib.sha256(json.dumps(grouping, sort_keys=True).encode()).hexdigest()
    result['endpoint_policy'] = policy
    result['probe_definitions'] = [{k: v for k, v in definition.items() if k != 'argv'} |
                                   ({'argv_sha256': hashlib.sha256(json.dumps(definition['argv']).encode()).hexdigest()}
                                    if 'argv' in definition else {}) for definition in settings.get('probes', [])]
    probes = []
    child = None
    pool = ThreadPoolExecutor(max_workers=2)
    future = reverse_future = None
    start_ns = dispatch_ns = effect_ns = reverse_ns = restored_ns = interrupted_ns = None
    previous_sample = None
    max_gap_ms = 0
    stable_effect = stable_restore = 0
    effect_candidate = restore_candidate = None
    audit_events = []
    journal = (folder / 'observations.jsonl').open('x')

    def mark(kind, **details):
        event = {'event': kind, 'at': utc_now(), 'monotonic_ns': time.monotonic_ns(), **details}
        journal.write(json.dumps(event) + '\n')
        journal.flush()
        if kind != 'sample':
            print(f'{case_id} {kind}: {json.dumps(details)}', flush=True)

    try:
        manifest = create_corpus(folder, settings, user.pw_uid, user.pw_gid)
        if action in ('kill', 'isolate', 'block', 'disable'):
            probes = [Probe(definition, settings['probe_timeout_seconds']) for definition in settings.get('probes', [])]
            roles = {probe.definition['role'] for probe in probes}
            if roles != {'restricted', 'preserved'}:
                raise ValueError('Network/account actions need restricted AND preserved probes')
            if action == 'block' and any(p.definition['type'] != 'tcp' or
                                         canonical_ip(p.definition['host']) != canonical_ip(settings['block_ip'])
                                         for p in probes if p.definition['role'] == 'restricted'):
                raise ValueError('Restricted IP-block probes must connect to the actual block_ip')
            if action == 'disable' and not any(p.definition['type'] == 'command' and
                                              p.definition['role'] == 'restricted' for p in probes):
                raise ValueError('Account evaluation needs a real fresh-login command probe')
            baseline = [probe.check() for probe in probes]
            if not probes_restored(baseline):
                raise ValueError('All target/control probes must succeed before applying any response')
            mark('baseline_probes', probes=baseline)
        runtime.store.create_case(actor=runtime.actor, title='M5 synthetic response evaluation', case_id=case_id)
        command = [sys.executable, str(Path(__file__).resolve()), '_workload', str(folder.resolve()),
                   '--interval', str(settings['write_interval_seconds']), '--duration', str(settings['duration_seconds'] + 2)]
        options = {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': []} if os.geteuid() == 0 else {}
        environment = clean_env() | {'HOME': user.pw_dir}
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=environment, start_new_session=True, **options)
        identity = runtime.identity(child.pid)
        if isinstance(runtime, OwnedProcessRuntime):
            runtime.owned_identity = identity
        result['workload_identity'] = identity
        ready_until = time.monotonic() + 3
        while not progress_read(folder)['first_write_ns']:
            if child.poll() is not None or time.monotonic() > ready_until:
                raise RuntimeError('Disposable workload did not start')
            time.sleep(.01)
        start_ns = progress_read(folder)['first_write_ns']
        end_ns = start_ns + int(settings['duration_seconds'] * 1e9)
        mark('workload_started', first_write_ns=start_ns, pid=child.pid)
        while time.monotonic_ns() < end_ns:
            now = time.monotonic_ns()
            if previous_sample is not None:
                max_gap_ms = max(max_gap_ms, milliseconds(previous_sample, now))
            previous_sample = now
            progress = progress_read(folder)
            code = child.poll()
            state = None
            if code is None:
                try:
                    state = runtime.identity(child.pid)['state']
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if action != 'baseline' and dispatch_ns is None and milliseconds(start_ns, now) >= settings['trigger_after_seconds'] * 1000:
                alert = build_alert(case_id, action, identity, settings, runtime.config['agent_id'])
                save_json(folder / 'synthetic-alert.json', alert)
                dispatch_ns = time.monotonic_ns()
                mark('dispatch_requested', transport=mode)
                if api:
                    future = pool.submit(api.dispatch, action, alert)
                else:
                    def dispatch_local():
                        wazuh(runtime, action, io.StringIO(json.dumps({'command': 'add', 'parameters': {'alert': alert}})
                                                          + '\n{"command":"continue"}\n'), io.StringIO())
                        return {'accepted': True, 'meaning': 'local adapter only; no manager contacted'}
                    future = pool.submit(dispatch_local)
            samples = [probe.check() for probe in probes]
            audit_events = runtime.store.timeline(case_id)
            audited = audit_success(audit_events, action)
            if dispatch_ns and interrupted_ns is None and (state in ('T', 't') or code == -signal.SIGKILL):
                interrupted_ns = time.monotonic_ns()
                mark('process_interruption_observed', proc_state=state, returncode=code)
            if action == 'freeze':
                effective = state in ('T', 't')
                restored = code is None and state not in (None, 'T', 't')
            elif action == 'kill':
                effective = code == -signal.SIGKILL and probes_effective(samples)
                restored = False
            else:
                effective, restored = probes_effective(samples), probes_restored(samples)
            observed_ns = time.monotonic_ns()
            mark('sample', proc_state=state, returncode=code, writes=progress['writes'], probes=samples,
                 action_audited=audited)
            if dispatch_ns and effect_ns is None:
                stable_effect = stable_effect + 1 if effective and audited else 0
                effect_candidate = (effect_candidate or observed_ns) if stable_effect else None
                if stable_effect >= settings['stable_samples']:
                    effect_ns = effect_candidate
                    result['writes_at_effect'] = progress['writes']
                    mark('effect_verified', effect_ns=effect_ns, writes=progress['writes'])
                elif milliseconds(dispatch_ns, observed_ns) > settings['effect_timeout_seconds'] * 1000:
                    raise TimeoutError('Containment effect not verified before the declared timeout')
            if effect_ns and reverse_ns is None and action != 'kill' and not effective:
                raise RuntimeError('Restriction disappeared before the measured reversal request')
            if effect_ns and action != 'kill' and reverse_ns is None and milliseconds(effect_ns, observed_ns) >= settings['hold_seconds'] * 1000:
                reverse_ns = time.monotonic_ns()
                result['writes_at_reversal_request'] = progress['writes']
                mark('reversal_requested', mechanism='local analyst CLI' if api else 'local workflow')
                reverse_future = pool.submit(reverse_installed, case_id, action) if api else pool.submit(reverse_local, runtime, case_id)
            if reverse_ns and restored_ns is None and observed_ns >= reverse_ns:
                own_reversal = any(x['event_type'] in ('response.thaw', 'response.undo') and x['outcome'] == 'success'
                                   and x['details'].get('reason') == 'evaluation measured reversal ' + case_id
                                   for x in audit_events)
                if action == 'freeze':
                    restored = restored and progress['writes'] > result['writes_at_reversal_request']
                stable_restore = stable_restore + 1 if restored and own_reversal else 0
                restore_candidate = (restore_candidate or observed_ns) if stable_restore else None
                if stable_restore >= settings['stable_samples']:
                    restored_ns = restore_candidate
                    mark('reversal_verified', restored_ns=restored_ns)
                elif milliseconds(reverse_ns, observed_ns) > settings['effect_timeout_seconds'] * 1000:
                    raise TimeoutError('Restoration not verified before the declared timeout')
            if restored_ns and milliseconds(restored_ns, observed_ns) < settings['post_reversal_seconds'] * 1000 and not restored:
                raise RuntimeError('Restoration did not remain effective during post-reversal observation')
            time.sleep(settings['sample_seconds'])
        if action != 'baseline' and (effect_ns is None or (action != 'kill' and restored_ns is None)):
            raise TimeoutError('Observation horizon ended before all required effects were verified')
        if restored_ns and milliseconds(restored_ns, time.monotonic_ns()) < settings['post_reversal_seconds'] * 1000:
            raise TimeoutError('Insufficient post-reversal observation')
        result['status'] = 'completed'
    except (Exception, KeyboardInterrupt) as exc:
        result['interrupted'] = isinstance(exc, KeyboardInterrupt)
        result['errors'].append({'phase': 'observation', 'type': type(exc).__name__, 'message': str(exc)})
        mark('failed', error_type=type(exc).__name__, message=str(exc))
    finally:
        # Cleanup has its own markers and can never count as a measured effect.
        mark('cleanup_started')
        if child is not None:
            if child.poll() is None:
                try:
                    child.send_signal(signal.SIGCONT)
                    child.terminate()
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
        try:
            finish_case(runtime, case_id)
            result['cleanup_complete'] = True
        except Exception as exc:
            result['cleanup_complete'] = False
            result['status'] = 'failed'
            result['errors'].append({'phase': 'cleanup', 'type': type(exc).__name__, 'message': str(exc)})
        pool.shutdown(wait=True)
        for pending, name in [(future, 'dispatch'), (reverse_future, 'reversal_dispatch')]:
            if pending:
                try:
                    result[name] = pending.result()
                except Exception as exc:
                    result[name] = {'error_type': type(exc).__name__}
        audit_events = runtime.store.timeline(case_id)
        received_ns = response_received_ns(audit_events, result['boot_id'])
        result['clock_events'] = {'workload_first_write_ns': start_ns, 'dispatch_requested_ns': dispatch_ns,
                                   'response_received_ns': received_ns, 'effect_observed_ns': effect_ns,
                                   'process_interruption_ns': interrupted_ns, 'reversal_requested_ns': reverse_ns,
                                   'restoration_observed_ns': restored_ns}
        result['metrics'] = {'workload_to_effect_ms': milliseconds(start_ns, effect_ns),
                             'dispatch_to_effect_ms': milliseconds(dispatch_ns, effect_ns),
                             'received_to_effect_ms': milliseconds(received_ns, effect_ns),
                             'workload_to_process_interruption_ms': milliseconds(start_ns, interrupted_ns),
                             'reversal_ms': milliseconds(reverse_ns, restored_ns),
                             'max_observer_gap_ms': max_gap_ms,
                             'sample_interval_ms': settings['sample_seconds'] * 1000,
                             'deadline_met': (effect_ns is not None and milliseconds(dispatch_ns, effect_ns)
                                              <= settings['effect_timeout_seconds'] * 1000)
                                             if dispatch_ns else None}
        if (folder / 'manifest.json').exists():
            result['damage'] = measure_damage(folder / 'corpus', json.loads((folder / 'manifest.json').read_text()))
        result['finished_at'] = utc_now()
        runtime.store.append_event(case_id, 'evaluation.result', actor=runtime.actor,
                                    outcome='success' if result['status'] == 'completed' else 'failure',
                                    details={'mode': mode, 'action': action, 'metrics': result['metrics'],
                                             'damage': {k: v for k, v in result.get('damage', {}).items()
                                                        if k not in ('damaged_file_ids', 'unreadable_paths')},
                                             'cleanup_complete': result['cleanup_complete']})
        save_json(folder / 'case.json', runtime.store.export_case(case_id))
        save_json(folder / 'result.json', result)
        mark('finished', status=result['status'], metrics=result['metrics'],
             damaged_files=result.get('damage', {}).get('damaged_files'))
        journal.close()
    return result


def percentile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    low, high = math.floor(position), math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def summarize(folder):
    groups = defaultdict(list)
    seen = set()
    for path in Path(folder).rglob('result.json'):
        result = json.loads(path.read_text())
        if result.get('schema_version') != 1 or 'evaluation_scope' not in result:
            continue
        if result['run_id'] in seen:
            raise ValueError('Duplicate run_id would inflate the evaluation sample')
        seen.add(result['run_id'])
        groups[(result['mode'], result['action'], result['configuration_sha256'])].append(result)
    rows = []
    for (mode, action, configuration), runs in sorted(groups.items()):
        passed = [run for run in runs if run['status'] == 'completed']
        row = {'mode': mode, 'action': action, 'configuration_sha256': configuration,
               'runs': len(runs), 'completed': len(passed), 'failed': len(runs) - len(passed),
               'completion_rate': len(passed) / len(runs),
               'cleanup_failures': sum(not r.get('cleanup_complete', False) for r in runs),
               'deadline_misses': sum(r['metrics'].get('deadline_met') is False for r in runs),
               'effect_timeouts': sum(r.get('clock_events', {}).get('dispatch_requested_ns') is not None
                                      and r['metrics'].get('dispatch_to_effect_ms') is None for r in runs)
                                  if action != 'baseline' else 0}
        for name in ('dispatch_to_effect_ms', 'received_to_effect_ms', 'workload_to_effect_ms', 'reversal_ms'):
            values = [r['metrics'][name] for r in runs if r['metrics'].get(name) is not None]
            row.update({name + '_n': len(values), name + '_median': statistics.median(values) if values else None,
                        name + '_p95': percentile(values, .95), name + '_max': max(values) if values else None})
        damage = [r['damage']['damaged_files'] for r in passed if 'damage' in r]
        row['damaged_files_mean_completed'] = statistics.mean(damage) if damage else None
        all_damage = [r['damage']['damaged_files'] for r in runs if 'damage' in r]
        row['damaged_files_mean_all_measured'] = statistics.mean(all_damage) if all_damage else None
        row['damage_reduction_vs_baseline'] = None
        rows.append(row)
    for row in rows:
        baseline_seeds = defaultdict(list)
        key = (row['mode'], 'baseline', row['configuration_sha256'])
        for baseline in groups.get(key, []):
            if baseline['status'] == 'completed' and 'damage' in baseline:
                baseline_seeds[baseline['seed']].append(baseline['damage']['damaged_files'])
        pairs = []
        if row['action'] != 'baseline':
            for run in groups[(row['mode'], row['action'], row['configuration_sha256'])]:
                if run['status'] == 'completed' and 'damage' in run and run.get('seed') in baseline_seeds:
                    pairs.append((run['damage']['damaged_files'], statistics.mean(baseline_seeds[run['seed']])))
        row['matched_baseline_runs'] = len(pairs)
        if pairs and sum(pair[1] for pair in pairs):
            row['damage_reduction_vs_baseline'] = 1 - sum(pair[0] for pair in pairs) / sum(pair[1] for pair in pairs)
    return rows


def write_summary(folder):
    rows = summarize(folder)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    target = Path(folder) / ('summary-' + stamp)
    save_json(target.with_suffix('.json'), {'schema_version': 1, 'groups': rows,
                                          'latency_population': 'all observed effects, including failed runs; missing effects reported separately',
                                          'damage_reduction_population': 'completed fixed-horizon runs only',
                                          'p95_note': 'small-sample estimates; no p99 claim'})
    with target.with_suffix('.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else ['runs'])
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({'summary': str(target), 'groups': rows}, indent=2))
    return rows


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '_workload':
        worker = argparse.ArgumentParser(description='Internal disposable workload')
        worker.add_argument('folder', type=Path)
        worker.add_argument('--interval', type=float, required=True)
        worker.add_argument('--duration', type=float, required=True)
        args = worker.parse_args(sys.argv[2:])
        workload(args.folder, args.interval, args.duration)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    local = commands.add_parser('process-check', help='Real files and owned child, local JSON adapter; no manager')
    local.add_argument('--output', type=Path, required=True)
    local.add_argument('--repetitions', type=int, default=1)
    live = commands.add_parser('run', help='Execute a real Wazuh AR response-stage experiment on this endpoint')
    live.add_argument('--config', type=Path, required=True)
    live.add_argument('--action', choices=['baseline', *SCRIPTS], required=True)
    live.add_argument('--output', type=Path, required=True)
    live.add_argument('--repetitions', type=int, default=1)
    commands.add_parser('summarize').add_argument('folder', type=Path)
    args = parser.parse_args()
    if args.command == 'summarize':
        write_summary(args.folder)
        return 0
    if not 1 <= args.repetitions <= 1000:
        parser.error('repetitions must be in [1, 1000]')
    if sys.platform != 'linux' or not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        parser.error('Use Ubuntu/Linux with pidfd support')
    if args.command == 'process-check':
        settings = settings_checked({'files': 200, 'duration_seconds': 2,
                                      'effect_timeout_seconds': .5, 'trigger_after_seconds': .1,
                                      'hold_seconds': .1, 'post_reversal_seconds': .1,
                                      'sample_seconds': .01, 'write_interval_seconds': .01})
        mode, actions = 'local-json-adapter', ['baseline', 'freeze']
        gid = os.getgid()
    else:
        if not (3, 10) <= sys.version_info[:2] < (3, 13):
            parser.error('Live endpoint runtime requires Python 3.10–3.12')
        settings = settings_checked(json.loads(args.config.read_text()))
        mode, actions = 'wazuh-api', [args.action]
        user, _ = live_preflight(settings, args.action)
        gid = user.pw_gid
    base = make_folder(args.output, gid)
    passed = True
    for index in range(args.repetitions):
        for action in actions:
            result = evaluate_one(base / f'{index + 1:03d}-{action}', action, settings, mode, index)
            passed = passed and result['status'] == 'completed'
            if not result['cleanup_complete']:
                print('Cleanup incomplete: inspect the case from the VM console before another run.', file=sys.stderr)
                write_summary(base)
                return 1
            if result.get('interrupted'):
                write_summary(base)
                return 130
    write_summary(base)
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, PermissionError, FileNotFoundError, KeyError) as exc:
        print(f'M5 evaluation: {exc}', file=sys.stderr)
        raise SystemExit(2)

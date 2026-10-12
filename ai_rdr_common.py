"""Linux response runtime: serialized state, durable intent, process identities."""
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from ai_rdr_aicm import CaseStore


class Runtime:
    def __init__(self, config=None):
        if config is None:
            path = Path(os.environ.get('AI_RDR_CONFIG', '/etc/ai-rdr/config.json'))
            config = json.loads(path.read_text())
        self.config = config
        self.directory = Path(config.get('state_dir', '/var/lib/ai-rdr'))
        self.log = Path(config.get('audit_log', '/var/log/ai-rdr/response.jsonl'))
        self._store = None
        self.actor = {'type': 'service', 'id': 'arm:' + config.get('agent_id', 'local')}
        self.request_id = None

    @property
    def store(self):
        if self._store is None:
            self._store = CaseStore(self.directory / 'aicm.sqlite3')
        return self._store

    def require_root(self):
        if os.geteuid() != 0:
            raise PermissionError('Active Response requires root')

    @contextlib.contextmanager
    def transaction(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.directory / 'response.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self.store.load_state()
            if state is None:
                path = self.directory / 'state.json'
                # One-time migration. Preserve the original JSON as a recovery archive.
                state = json.loads(path.read_text()) if path.exists() else {'resources': {}, 'cases': {}}
                if path.exists():
                    self.save(state)
            yield state

    def save(self, state):
        self.store.save_state(state, actor=self.actor, request_id=self.request_id)

    def audit(self, action, case_id, status, **details):
        operation_id = details.pop('operation_id', None)
        outcome = 'failure' if status in ('FAILED', 'PARTIAL', 'REJECTED', 'STALE_BOOT') else (
            'unknown' if status == 'REVIEW_REQUIRED' else 'success')
        self.store.append_event(case_id, 'response.' + action, actor=self.actor,
                                request_id=self.request_id, operation_id=operation_id,
                                outcome=outcome, details={'result': status, **details})

    def run(self, args, check=True):
        return subprocess.run(args, check=check, capture_output=True, text=True, timeout=2)

    def boot_id(self):
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def identity(self, pid):
        pid = int(pid)
        if pid <= 1 or pid == os.getpid():
            raise ValueError('Protected PID')
        stat = Path(f'/proc/{pid}/stat').read_text()
        fields = stat[stat.rfind(')') + 2:].split()
        status = Path(f'/proc/{pid}/status').read_text().splitlines()
        uid = int(next(x for x in status if x.startswith('Uid:')).split()[1])
        name = Path(f'/proc/{pid}/comm').read_text().strip()
        return {'pid': pid, 'start_ticks': int(fields[19]), 'boot_id': self.boot_id(),
                'uid': uid, 'name': name, 'state': fields[0], 'ppid': int(fields[1])}

    def protected(self, identity):
        return (identity['uid'] < self.config.get('minimum_process_uid', 1000)
                or identity['name'] in self.config.get('protected_processes', [])
                or identity['name'].startswith('wazuh-'))

    def signal_identity(self, identity, sig):
        # Open first, then check identity. pidfd_send_signal cannot hit a reused PID.
        fd = os.pidfd_open(identity['pid'])
        try:
            current = self.identity(identity['pid'])
            if any(current[k] != identity[k] for k in ('start_ticks', 'boot_id', 'uid')):
                raise ValueError('Process identity changed')
            if self.protected(current):
                raise ValueError('Protected process')
            signal.pidfd_send_signal(fd, sig)
        finally:
            os.close(fd)

    def wait_effect(self, identity, stopped=False):
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                current = self.identity(identity['pid'])
            except FileNotFoundError:
                return not stopped
            if current['start_ticks'] != identity['start_ticks'] or current['boot_id'] != identity['boot_id']:
                return not stopped
            if stopped and current['state'] in ('T', 't'):
                return True
            if not stopped and current['state'] in ('Z', 'X'):
                return True
            time.sleep(0.01)
        return False

    def wait_resumed(self, identity):
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                current = self.identity(identity['pid'])
            except FileNotFoundError:
                return True
            if any(current[k] != identity[k] for k in ('start_ticks', 'boot_id')):
                return True  # Original target no longer exists.
            if current['state'] not in ('T', 't'):
                return True
            time.sleep(0.01)
        return False

    def children(self, pid):
        result = []
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                child = self.identity(int(path.name))
                if child['ppid'] == pid:
                    result.append(child)
            except (FileNotFoundError, ProcessLookupError, ValueError):
                continue
        return result


def canonical_ip(value):
    address = ipaddress.ip_address(value)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError('Protected/invalid network target')
    return str(address)

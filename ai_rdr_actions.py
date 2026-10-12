"""Shared playbooks. Call under Runtime.transaction; persist before mutations."""
import pwd
import re
import signal
import time

from ai_rdr_common import canonical_ip


class Actions:
    def __init__(self, runtime):
        self.r = runtime

    def firewall(self, kind, target, add):
        managers = [canonical_ip(x) for x in self.r.config.get('manager_addresses', [])]
        if not managers:
            raise ValueError('Configure manager_addresses before firewall response')
        if kind == 'block' and target in managers:
            raise ValueError('Cannot block a Wazuh manager')
        for tool, version in [('iptables', 4), ('ip6tables', 6)]:
            if kind == 'block' and (':' in target) != (version == 6):
                continue
            if kind == 'isolate':
                specifications = []
                for parent, chain, direction in [('INPUT', 'AI_RDR_ISO_IN', '-s'),
                                                  ('OUTPUT', 'AI_RDR_ISO_OUT', '-d')]:
                    rules = [['-i' if parent == 'INPUT' else '-o', 'lo', '-j', 'ACCEPT']]
                    for manager in managers:
                        if (':' in manager) == (version == 6):
                            for port in self.r.config.get('manager_ports', [1514]):
                                if not isinstance(port, int) or not 1 <= port <= 65535:
                                    raise ValueError('Invalid manager port')
                                rules.append([direction, manager, '-p', 'tcp',
                                              '--sport' if parent == 'INPUT' else '--dport',
                                              str(port), '-j', 'ACCEPT'])
                    rules.append(['-j', 'DROP'])
                    specifications.append((parent, chain, rules))
            else:
                specifications = [('INPUT', 'AI_RDR_BLOCK_IN', [['-s', target, '-j', 'DROP']]),
                                  ('OUTPUT', 'AI_RDR_BLOCK_OUT', [['-d', target, '-j', 'DROP']])]
            for parent, chain, rules in specifications:
                def command(*args, check=True):
                    return self.r.run([tool, '-w', '1', *args], check=check)
                exists = command('-S', chain, check=False)
                if exists.returncode and not add:
                    # Distinguish a missing chain from a broken firewall backend.
                    command('-S')
                    continue
                if exists.returncode:
                    command('-N', chain)
                if add:
                    for rule in rules:
                        if command('-C', chain, *rule, check=False).returncode:
                            command('-A', chain, *rule)
                    if command('-C', parent, '-j', chain, check=False).returncode:
                        command('-I', parent, '1', '-j', chain)
                    # Command success alone is insufficient; verify installed rules.
                    for rule in rules:
                        command('-C', chain, *rule)
                    command('-C', parent, '-j', chain)
                else:
                    if kind == 'isolate':
                        while command('-C', parent, '-j', chain, check=False).returncode == 0:
                            command('-D', parent, '-j', chain)
                        command('-F', chain)
                        command('-X', chain)
                    else:
                        for rule in rules:
                            while command('-C', chain, *rule, check=False).returncode == 0:
                                command('-D', chain, *rule)
                        command('-S', chain)

    def account_snapshot(self, username):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', username):
            raise ValueError('Invalid username')
        user = pwd.getpwnam(username)
        if user.pw_uid < 1000 or username in self.r.config.get('protected_users', []):
            raise ValueError('Protected account')
        # Only local /etc/shadow accounts. Store metadata, never password hashes.
        import spwd
        entry = spwd.getspnam(username)
        return {'uid': user.pw_uid, 'locked': entry.sp_pwdp.startswith(('!', '*')),
                'expiry': entry.sp_expire}

    def account(self, target, add, previous):
        current = self.account_snapshot(target)
        if current['uid'] != previous['uid']:
            raise ValueError('Account identity changed')
        if add:
            self.r.run(['usermod', '-L', '-e', '1', target])
            now = self.account_snapshot(target)
            if not now['locked'] or now['expiry'] != 1:
                raise RuntimeError('Account restriction not effective')
        else:
            if (current['locked'], current['expiry']) == (previous['locked'], previous['expiry']):
                return  # Recover a crash after restoration but before durable completion.
            # Do not overwrite an administrator's intervening expiry change.
            if current['expiry'] != 1:
                raise RuntimeError('Account changed externally; analyst reconciliation required')
            args = ['usermod', '-e', str(previous['expiry']) if previous['expiry'] >= 0 else '']
            if not previous['locked']:
                args.append('-U')
            self.r.run([*args, target])
            now = self.account_snapshot(target)
            if now['locked'] != previous['locked'] or now['expiry'] != previous['expiry']:
                raise RuntimeError('Account restoration not effective')

    def reversible(self, state, kind, target, case_id, add):
        started = time.monotonic()
        if kind == 'block':
            target = canonical_ip(target)
        key = f'{kind}:{target}'
        resources = state['resources']
        record = resources.get(key)
        if add:
            if record is None:
                record = {'owners': [], 'status': 'PENDING', 'kind': kind, 'target': target}
                if kind == 'disable':
                    record['previous'] = self.account_snapshot(target)
                resources[key] = record
            if case_id not in record['owners']:
                record['owners'].append(case_id)
            self.r.save(state)
            if record['status'] != 'APPLIED':
                self._apply(record, True)
                record['status'] = 'APPLIED'
                self.r.save(state)
        else:
            if record is None or case_id not in record['owners']:
                return  # Unknown delete must not change another case's resources.
            if len(record['owners']) > 1:
                record['owners'].remove(case_id)
                self.r.save(state)
                self.r.audit(kind, case_id, 'LEASE_RELEASED', target=target,
                             remaining_owners=len(record['owners']))
                return
            record['status'] = 'REMOVING'
            self.r.save(state)
            self._apply(record, False)
            del resources[key]
            self.r.save(state)
        self.r.audit(kind, case_id, 'APPLIED' if add else 'REMOVED', target=target,
                     elapsed_ms=(time.monotonic() - started) * 1000)

    def _apply(self, record, add):
        if record['kind'] == 'disable':
            self.account(record['target'], add, record['previous'])
        else:
            self.firewall(record['kind'], record['target'], add)

    def reconcile(self, state):
        for key, record in list(state['resources'].items()):
            if record['status'] == 'APPLIED':
                continue
            self._apply(record, record['status'] != 'REMOVING')
            if record['status'] == 'REMOVING':
                del state['resources'][key]
            else:
                record['status'] = 'APPLIED'
            self.r.save(state)

    def kill(self, identities, case_id, operation_id=None):
        started = time.monotonic()
        errors = []
        for identity in reversed(identities):
            try:
                self.r.signal_identity(identity, signal.SIGKILL)
                if not self.r.wait_effect(identity):
                    raise RuntimeError('Termination deadline exceeded')
            except (FileNotFoundError, ProcessLookupError):
                continue
            except Exception as exc:
                errors.append({'pid': identity['pid'], 'error': str(exc)})
        self.r.audit('kill', case_id, 'PARTIAL' if errors else 'SUCCESS', errors=errors,
                     operation_id=operation_id, reversible=False,
                     elapsed_ms=(time.monotonic() - started) * 1000)
        if errors:
            raise RuntimeError('Process termination incomplete')

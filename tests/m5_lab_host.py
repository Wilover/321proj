"""In-memory OS boundary for manual M5 demonstrations. Never runs OS commands."""
import copy
import signal
import subprocess

from ai_rdr_common import Runtime


class LabHost:
    def __init__(self):
        self.processes = {}
        self.users = {'labuser': {'uid': 1001, 'locked': False, 'expiry': -1}}
        self.tables = {tool: {'INPUT': [['-j', 'UNRELATED']], 'OUTPUT': [['-j', 'UNRELATED']],
                              'UNRELATED': [['-j', 'RETURN']]}
                       for tool in ('iptables', 'ip6tables')}
        self.calls = []
        self.signals = []

    def process(self, pid, ppid=1, state='S'):
        self.processes[pid] = {'pid': pid, 'ppid': ppid, 'start_ticks': pid * 100,
                               'boot_id': 'SIMULATED-BOOT', 'uid': 1001,
                               'name': 'lab-workload', 'state': state}
        return dict(self.processes[pid])


class LabRuntime(Runtime):
    def __init__(self, directory, emit, host=None):
        super().__init__({'state_dir': str(directory), 'agent_id': 'LAB-001',
                          'manager_addresses': ['192.0.2.62'], 'manager_ports': [1514],
                          'controller_addresses': ['192.0.2.63'], 'controller_ssh_port': 22,
                          'verification_seconds': 3, 'timeout_policy': 'thaw',
                          'protected_users': ['admin'], 'require_approval': False})
        self.host = host or LabHost()
        self.emit = emit

    def boot_id(self):
        return 'SIMULATED-BOOT'

    def identity(self, pid):
        if int(pid) not in self.host.processes:
            raise FileNotFoundError('Simulated process is absent')
        return dict(self.host.processes[int(pid)])

    def children(self, pid):
        return [dict(x) for x in self.host.processes.values() if x['ppid'] == pid]

    def signal_identity(self, identity, sig):
        current = self.identity(identity['pid'])
        if any(current[k] != identity[k] for k in ('boot_id', 'start_ticks', 'uid')):
            raise ValueError('Process identity changed')
        if self.protected(current):
            raise ValueError('Protected process')
        self.host.signals.append((identity['pid'], sig))
        self.host.processes[identity['pid']]['state'] = {
            signal.SIGSTOP: 'T', signal.SIGCONT: 'S', signal.SIGKILL: 'Z'}[sig]
        self.emit(f'[SIMULATED HOST] {signal.Signals(sig).name} pid={identity["pid"]}')

    def account_snapshot(self, username):
        if username in self.config['protected_users']:
            raise ValueError('Protected account')
        return dict(self.host.users[username])

    def run(self, args, check=True):
        self.host.calls.append(list(args))
        self.emit('[SIMULATED HOST] ' + ' '.join(args))
        stdout = ''
        code = 0
        if args[0] in self.host.tables:
            table = self.host.tables[args[0]]
            arguments = args[3:]  # Production code always uses -w 1.
            verb = arguments[0]
            chain = arguments[1] if len(arguments) > 1 else None
            rule = arguments[2:]
            if verb == '-S':
                code = int(chain is not None and chain not in table)
                stdout = '\n'.join('-A ' + name + ' ' + ' '.join(item)
                                   for name, rules in table.items() if chain in (None, name)
                                   for item in rules)
            elif verb == '-N':
                code = int(chain in table)
                if not code:
                    table[chain] = []
            elif chain not in table:
                code = 1
            elif verb == '-C':
                code = int(rule not in table[chain])
            elif verb == '-A':
                table[chain].append(rule)
            elif verb == '-I':
                table[chain].insert(int(rule[0]) - 1, rule[1:])
            elif verb == '-D':
                if rule in table[chain]:
                    table[chain].remove(rule)
                else:
                    code = 1
            elif verb == '-F':
                table[chain].clear()
            elif verb == '-X':
                if table[chain]:
                    code = 1
                else:
                    del table[chain]
            else:
                raise AssertionError('Unsupported simulated firewall operation')
        elif args[0] == 'usermod':
            user = self.host.users[args[-1]]
            if '-L' in args:
                user['locked'] = True
            if '-U' in args:
                user['locked'] = False
            if '-e' in args:
                expiry = args[args.index('-e') + 1]
                user['expiry'] = int(expiry) if expiry else -1
        else:
            raise AssertionError('Real command execution is forbidden in this demo')
        result = subprocess.CompletedProcess(args, code, stdout, 'simulated command failure' if code else '')
        if check:
            result.check_returncode()
        return result

    def snapshot(self):
        return copy.deepcopy({'processes': self.host.processes, 'users': self.host.users,
                              'firewall': self.host.tables})

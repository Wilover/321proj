#!/usr/bin/env python3
"""M5 endpoint JSON gateway and dependency-free client for the M6 backend.

Run the gateway through a fixed, restricted SSH command, never as a public HTTP
server. The trusted M6 backend signs its authenticated principal; browser claims
are not authority. Importing the client does not import Linux executor modules.
"""
import argparse
from copy import deepcopy
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


MAX_REQUEST = 65536
MAX_RESPONSE = 1024 * 1024
MANUAL_ACTIONS = ('freeze', 'verify', 'kill', 'isolate', 'thaw', 'undo', 'approve_containment')
ROLE_PERMISSIONS = {
    'viewer': ['read'],
    'analyst': ['read', 'freeze', 'verify', 'thaw', 'undo'],
    'responder': ['read', *MANUAL_ACTIONS],
    'connector': ['read', 'deliver'],
}


class GatewayError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def text(value, name, limit=256):
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(c) < 32 for c in value)):
        raise GatewayError('bad_request', 'Invalid ' + name)
    return value


def instant(value):
    parsed = dt.datetime.fromisoformat(text(value, 'timestamp').replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GatewayError('bad_request', 'Timezone-aware timestamp required')
    return parsed.astimezone(dt.timezone.utc)


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value):
    return value.astimezone(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def signed(body, key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError('Gateway key must contain at least 32 bytes')
    body = {k: v for k, v in body.items() if k != 'signature'}
    return body | {'signature': hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest()}


def verify_signature(body, key):
    signature = body.get('signature') if isinstance(body, dict) else None
    if (not isinstance(signature, str) or not re.fullmatch(r'[0-9a-f]{64}', signature)
            or not hmac.compare_digest(signed(body, key)['signature'], signature)):
        raise GatewayError('unauthenticated', 'Invalid gateway signature')


def request_identity(agent_id, principal, idempotency_key):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, canonical(
        ['m5-m6-action', agent_id, principal['type'], principal['id'], idempotency_key])))


class M6Gateway:
    def __init__(self, runtime, key, clock=utc_now):
        self.r, self.key, self.clock = runtime, key, clock
        self.config = runtime.config.get('m6_gateway', {})
        self.agent_id = text(runtime.config.get('agent_id'), 'endpoint identity')
        signed({}, key)  # Validate configuration without logging a secret.
        self.executor = {'type': 'service', 'id': 'm5-gateway:' + self.agent_id,
                         'unix_uid': os.geteuid()}

    def _authenticate(self, packet):
        if self.config.get('enabled') is not True:
            raise GatewayError('disabled', 'M6 gateway is disabled on this endpoint')
        if len(canonical(packet).encode()) > MAX_REQUEST:
            raise GatewayError('bad_request', 'Gateway request exceeds 64 KiB')
        verify_signature(packet, self.key)
        if set(packet) != {'version', 'issuer', 'agent_id', 'request_id', 'sent_at', 'expires_at',
                           'principal', 'method', 'params', 'signature'}:
            raise GatewayError('bad_request', 'Invalid request envelope')
        if (type(packet['version']) is not int or packet['version'] != 1
                or packet['issuer'] != self.config.get('issuer', 'm6-backend')
                or packet['agent_id'] != self.agent_id):
            raise GatewayError('forbidden', 'Wrong gateway issuer, version or endpoint')
        text(packet['request_id'], 'transport request ID')
        start, expiry = instant(packet['sent_at']), instant(packet['expires_at'])
        now = self.clock()
        if (not 0 < (expiry - start).total_seconds() <= 120 or now >= expiry
                or (start - now).total_seconds() > 30):
            raise GatewayError('expired', 'Request expired or exceeds clock-skew/lifetime limits')
        principal = packet['principal']
        if (not isinstance(principal, dict) or set(principal) != {'type', 'id', 'roles'}
                or principal['type'] not in ('user', 'service')):
            raise GatewayError('forbidden', 'Invalid authenticated principal')
        text(principal['id'], 'principal identity')
        roles = principal['roles']
        if not isinstance(roles, list) or not 0 < len(roles) <= 8:
            raise GatewayError('forbidden', 'Invalid principal roles')
        mapping = self.config.get('role_permissions', ROLE_PERMISSIONS)
        if (not isinstance(mapping, dict) or any(not isinstance(role, str) or role not in mapping for role in roles)
                or any(not isinstance(values, list) or any(x not in ('read', 'deliver', *MANUAL_ACTIONS) for x in values)
                       for values in mapping.values())):
            raise GatewayError('forbidden', 'Unknown role or invalid endpoint permission policy')
        permissions = {p for role in roles for p in mapping[role]}
        if not isinstance(packet['params'], dict):
            raise GatewayError('bad_request', 'Method params must be an object')
        return principal, permissions

    def handle(self, packet):
        request_id = packet.get('request_id') if isinstance(packet, dict) else None
        principal = None
        response = {'version': 1, 'agent_id': self.agent_id, 'request_id': request_id,
                    'server_time': timestamp(self.clock())}
        try:
            principal, permissions = self._authenticate(packet)
            response.update(ok=True, result=self._dispatch(packet['method'], packet['params'], principal,
                                                          permissions, instant(packet['expires_at'])))
        except Exception as exc:
            # Return controlled diagnostics, never arbitrary exceptions/credentials.
            from ai_rdr_aicm import Conflict
            code = (exc.code if isinstance(exc, GatewayError) else 'conflict' if isinstance(exc, Conflict)
                    else 'not_found' if isinstance(exc, KeyError) else 'forbidden' if isinstance(exc, PermissionError)
                    else 'bad_request' if isinstance(exc, (ValueError, TypeError)) else 'unavailable')
            message = str(exc) if isinstance(exc, (GatewayError, Conflict)) else {
                'not_found': 'Case, operation or request not found', 'forbidden': 'Action not permitted',
                'bad_request': 'Invalid request parameters', 'unavailable': 'M5 could not complete the request',
            }[code]
            if principal is not None and packet['method'] == 'request_action':
                try:
                    self.r.store.append_event(None, 'analyst.request_rejected',
                        actor={'type': principal['type'], 'id': principal['id']}, request_id=packet['request_id'],
                        phase='rejected', outcome='failure', details={'code': code, 'executor': self.executor})
                except Exception:
                    pass  # Denial remains a denial if storage is unavailable.
            response.update(ok=False, error={'code': code, 'message': message})
        if len(canonical(response).encode()) > MAX_RESPONSE - 256:
            response = {k: response[k] for k in ('version', 'agent_id', 'request_id', 'server_time')}
            response.update(ok=False, error={'code': 'response_too_large', 'message': 'Reduce the requested page size'})
        return signed(response, self.key)

    @staticmethod
    def _params(params, allowed, required=()):
        if set(params) - set(allowed) or set(required) - set(params):
            raise GatewayError('bad_request', 'Unexpected or missing method parameter')

    @staticmethod
    def _page(params):
        limit, after = params.get('limit', 100), params.get('after', 0)
        if type(limit) is not int or not 1 <= limit <= 100 or type(after) is not int or after < 0:
            raise GatewayError('bad_request', 'Invalid page limit/cursor')
        return limit, after

    def _dispatch(self, method, params, principal, permissions, deadline):
        if method == 'request_action':
            return self._action(params, principal, permissions, deadline)
        permission = 'deliver' if method in ('outbox', 'acknowledge') else 'read'
        if permission not in permissions:
            raise GatewayError('forbidden', 'Endpoint role does not permit this method')
        if method in ('outbox', 'acknowledge') and principal['type'] != 'service':
            raise GatewayError('forbidden', 'Event delivery requires an authenticated service principal')
        if method == 'health':
            self._params(params, ())
            return {'schema_version': 1, 'agent_id': self.agent_id, 'boot_id': self.r.boot_id(),
                    'gateway_ready': True, 'worker_status': 'not_observed', 'manual_actions': list(MANUAL_ACTIONS)}
        if method == 'list_cases':
            self._params(params, ('limit', 'offset'))
            limit, _ = self._page(params)
            offset = params.get('offset', 0)
            if type(offset) is not int or offset < 0:
                raise GatewayError('bad_request', 'Invalid offset')
            return {'agent_id': self.agent_id, 'items': self.r.store.list_cases(limit, offset),
                    'limit': limit, 'offset': offset}
        if method == 'get_case':
            self._params(params, ('case_id', 'limit'), ('case_id',))
            case_id = text(params['case_id'], 'case ID')
            limit, _ = self._page(params)
            # Operation, case and resource state vocabularies stay distinct.
            with self.r.store.connection() as db:
                case = db.execute('SELECT * FROM cases WHERE case_id=?', (case_id,)).fetchone()
                if case is None:
                    raise KeyError(case_id)
                operations = [dict(x) | {'target': json.loads(x['target']), 'details': json.loads(x['details'])}
                              for x in db.execute('SELECT * FROM operations WHERE case_id=? '
                                                  'ORDER BY updated_at DESC,operation_id LIMIT ?', (case_id, limit))]
                count = db.execute('SELECT COUNT(*) FROM operations WHERE case_id=?', (case_id,)).fetchone()[0]
                row = db.execute("SELECT payload FROM audit_events WHERE case_id=? AND event_type='risk.decided' "
                                 'ORDER BY sequence DESC LIMIT 1', (case_id,)).fetchone()
            return {'agent_id': self.agent_id, 'case': dict(case),
                    'latest_risk_decision': json.loads(row[0])['details']['decision'] if row else None,
                    'process_operations': [x for x in operations if x['kind'] == 'process_tree'],
                    'resource_operations': [x for x in operations if x['kind'] != 'process_tree'],
                    'operation_count': count, 'operations_truncated': count > len(operations),
                    'observation': 'Persisted states; APPLIED is not a continuous live network probe'}
        if method in ('timeline', 'risk_decisions'):
            self._params(params, ('case_id', 'limit', 'after'), ('case_id',))
            case_id = text(params['case_id'], 'case ID')
            with self.r.store.connection() as db:
                if not db.execute('SELECT 1 FROM cases WHERE case_id=?', (case_id,)).fetchone():
                    raise KeyError(case_id)
            limit, after = self._page(params)
            if method == 'timeline':
                events = self.r.store.timeline(case_id, after=after, limit=limit)
            else:
                with self.r.store.connection() as db:
                    rows = db.execute("SELECT payload FROM audit_events WHERE case_id=? AND sequence>? "
                                      "AND event_type='risk.decided' ORDER BY sequence LIMIT ?",
                                      (case_id, after, limit)).fetchall()
                events = [json.loads(row[0]) for row in rows]
            return {'agent_id': self.agent_id, 'items': events,
                    'next_after': events[-1]['case_sequence'] if events else after}
        if method == 'get_action':
            self._params(params, ('request_id',), ('request_id',))
            return self.r.store.analyst_request(text(params['request_id'], 'action request ID'))
        if method == 'outbox':
            self._params(params, ('limit',))
            limit, _ = self._page(params)
            return {'agent_id': self.agent_id, 'items': self.r.store.pending_events(limit)}
        if method == 'acknowledge':
            self._params(params, ('event_ids',), ('event_ids',))
            ids = params['event_ids']
            if not isinstance(ids, list) or not 1 <= len(ids) <= 100:
                raise GatewayError('bad_request', 'Acknowledge 1–100 event IDs')
            for event_id in ids:
                text(event_id, 'event ID')
            return {'acknowledged': self.r.store.acknowledge(ids)}
        raise GatewayError('not_found', 'Unknown gateway method')

    def _action(self, params, principal, permissions, deadline):
        self._params(params, ('case_id', 'action', 'reason', 'idempotency_key', 'expected_sequence',
                              'operation_id', 'target', 'resource_key'),
                     ('case_id', 'action', 'reason', 'idempotency_key', 'expected_sequence'))
        action = params['action']
        allowed = self.config.get('allowed_actions', list(MANUAL_ACTIONS))
        if (principal['type'] != 'user' or action not in MANUAL_ACTIONS or action not in permissions
                or not isinstance(allowed, list) or action not in allowed):
            raise GatewayError('forbidden', 'Analyst role/endpoint policy does not permit this action')
        case_id = text(params['case_id'], 'case ID')
        text(params['reason'], 'analyst reason', 1024)
        text(params['idempotency_key'], 'idempotency key', 128)
        if type(params['expected_sequence']) is not int or params['expected_sequence'] < 0:
            raise GatewayError('bad_request', 'Expected case sequence must be an integer')
        request_id = request_identity(self.agent_id, principal, params['idempotency_key'])
        actor = {'type': principal['type'], 'id': principal['id']}
        old_actor, old_request = self.r.actor, self.r.request_id
        try:
            self.r.actor, self.r.request_id = actor, request_id
            with self.r.transaction() as state:
                if self.clock() >= deadline:
                    raise GatewayError('expired', 'Request expired while waiting for the executor')
                created = self.r.store.begin_analyst_request(case_id, request_id, params, actor=actor,
                    executor=self.executor, expected_sequence=params['expected_sequence'])
                if not created:
                    return self.r.store.analyst_request(request_id)
                self._phase(case_id, request_id, 'started', actor, outcome='unknown')
                try:
                    if self.clock() >= deadline:
                        raise GatewayError('expired', 'Request expired before dispatch')
                    result = self._execute(state, case_id, action, params)
                except Exception as exc:
                    from ai_rdr_aicm import Conflict
                    code = (exc.code if isinstance(exc, GatewayError) else
                            'conflict' if isinstance(exc, (Conflict, KeyError, ValueError)) else
                            'forbidden' if isinstance(exc, PermissionError) else 'execution_failed')
                    self._phase(case_id, request_id, 'failed', actor, outcome='failure',
                                error={'code': code, 'message': 'Action did not complete; inspect operation state',
                                       'error_type': type(exc).__name__})
                else:
                    self._phase(case_id, request_id, 'completed', actor, outcome='success', result=result)
                return self.r.store.analyst_request(request_id)
        finally:
            self.r.actor, self.r.request_id = old_actor, old_request

    def _phase(self, case_id, request_id, phase, actor, outcome, **details):
        self.r.store.append_event(case_id, 'analyst.' + phase, actor=actor, request_id=request_id,
            event_id='m6:' + request_id + ':' + phase, phase='started' if phase == 'started' else 'completed',
            outcome=outcome, details={'executor': self.executor, **details})

    def _execute(self, state, case_id, action, params):
        from ai_rdr_actions import Actions
        from ai_rdr_policy import process_identity_valid, attributed_decoy
        from freeze_verify_manager import Workflow, TERMINAL
        from ai_rdr_aicm import Conflict
        workflow = Workflow(self.r)
        reason = params['reason']
        if action == 'undo':
            if 'target' in params or 'operation_id' in params:
                raise ValueError('Undo selects a resource key, not a process')
            key = text(params.get('resource_key'), 'resource key')
            resource = state['resources'].get(key)
            if not resource or case_id not in resource['owners']:
                raise Conflict('Case does not own this restriction')
            kind, target = resource['kind'], resource['target']
            Actions(self.r).reversible(state, kind, target, case_id, False)
            remaining = state['resources'].get(key, {}).get('owners', [])
            return {'resource_key': key, 'ownership_released': True, 'remaining_owners': remaining,
                    'restriction_removed': not remaining}
        if 'resource_key' in params:
            raise ValueError('Resource keys are only valid for Undo')
        if action == 'freeze':
            target = params.get('target')
            if not process_identity_valid(target) or set(target) != {'pid', 'start_ticks', 'boot_id'}:
                raise ValueError('Freeze requires a complete immutable process target')
            if self.r.identity(target['pid'])['state'] in ('Z', 'X'):
                raise Conflict('Process has already exited')
            operation = params.get('operation_id')
            if operation is None:
                candidates = [key for key, record in state['cases'].items()
                              if record.get('case_id', key) == case_id and record['status'] not in TERMINAL
                              and all(record['root'][k] == target[k] for k in target)]
                if len(candidates) > 1:
                    raise Conflict('Ambiguous process operation')
                operation = candidates[0] if candidates else str(uuid.uuid5(uuid.NAMESPACE_URL,
                    canonical(['manual-freeze', case_id, self.r.request_id, target])))
            if operation in state['cases']:
                existing = state['cases'][operation]
                if existing.get('case_id', operation) != case_id or existing['status'] not in ('FROZEN', 'REVIEW'):
                    raise Conflict('Operation is not eligible for manual Freeze')
            record = workflow.freeze(state, case_id, target['pid'], target['start_ticks'], target['boot_id'],
                                     None, operation_id=operation, manual_permission=True, reason=reason)
            record['status'] = 'REVIEW'
            self.r.save(state)
            return {'operation_id': operation, 'process_state': record['status'], 'manual_review': True}
        if 'target' in params:
            raise ValueError('Select an existing operation for this action')
        key = workflow.operation_key(state, case_id, params.get('operation_id'))
        record = state['cases'][key]
        if action == 'thaw':
            if record['status'] not in ('FROZEN', 'REVIEW', 'THAWING', 'THAWED'):
                raise Conflict('Operation cannot be thawed')
            workflow.thaw(state, case_id, reason, operation_id=key)
            return {'operation_id': key, 'process_state': record['status'], 'network_undo_performed': False,
                    'preserved_stops': [x['pid'] for x in record['processes'] if not x['ai_rdr_stopped']]}
        observations = []
        for item in record['processes']:
            try:
                current = self.r.identity(item['pid'])
                match = all(current[k] == item[k] for k in ('pid', 'start_ticks', 'boot_id', 'uid'))
                observations.append({'pid': item['pid'], 'identity_matches': match,
                                     'stopped': match and current['state'] in ('T', 't'),
                                     'protected': self.r.protected(current)})
            except (OSError, ValueError):
                observations.append({'pid': item['pid'], 'identity_matches': False, 'stopped': False, 'protected': False})
        verified = bool(observations) and all(x['identity_matches'] and not x['protected'] for x in observations)
        stopped = verified and all(x['stopped'] for x in observations)
        if action == 'verify':
            return {'operation_id': key, 'process_state': record['status'], 'identity_valid': verified,
                    'all_stopped': stopped, 'processes': observations,
                    'attributed_decoy': attributed_decoy(record.get('evidence'), record['root']),
                    'analyst_approved': record.get('analyst_approved') is True,
                    'malicious_verdict': 'not_determined_by_identity_check'}
        if record['status'] not in ('FROZEN', 'REVIEW') or not stopped:
            raise Conflict('Containment requires the current process tree to be frozen first')
        if action == 'isolate':
            record.update(manual_review=True, status='REVIEW')
            self.r.save(state)  # Hold for review before the network effect.
            Actions(self.r).reversible(state, 'isolate', 'host', case_id, True)
            # APPLIED may predate external firewall changes. An explicit manual
            # isolation request re-establishes/verifies the owned rules.
            Actions(self.r).firewall('isolate', 'host', True)
            return {'operation_id': key, 'process_state': record['status'],
                    'network_state': 'APPLIED', 'process_terminated': False}
        if action in ('kill', 'approve_containment'):
            workflow.contain(state, case_id, isolate=action == 'approve_containment', operation_id=key,
                             manual_permission=True, reason=reason)
            return {'operation_id': key, 'process_state': record['status'],
                    'isolation_requested': action == 'approve_containment', 'reversible': False}
        raise GatewayError('bad_request', 'Unsupported manual action')


class SSHTransport:
    """Fixed endpoint command, verified host key, no shell-interpolated request data."""
    COMMAND = ('sudo -n /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_m6.py '
               '--config /etc/ai-rdr/config.json')

    def __init__(self, host, user, identity_file, *, port=22, known_hosts_file=None, timeout=45):
        if (not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]{1,255}', host)
                or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user)
                or type(port) is not int or not 1 <= port <= 65535):
            raise ValueError('Invalid SSH destination')
        self.command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                        '-o', 'ConnectTimeout=10', '-p', str(port), '-i', str(identity_file)]
        if known_hosts_file:
            self.command += ['-o', 'UserKnownHostsFile=' + str(known_hosts_file)]
        self.command += [user + '@' + host, self.COMMAND]
        self.timeout = timeout

    def __call__(self, message):
        try:
            result = subprocess.run(self.command, input=message + '\n', capture_output=True,
                                    text=True, timeout=self.timeout, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GatewayError('transport_uncertain', 'SSH unavailable; check action status before retrying') from exc
        if not result.stdout or len(result.stdout.encode()) > MAX_RESPONSE:
            raise GatewayError('transport_uncertain', 'No bounded gateway response; check action status')
        return result.stdout


class M5Client:
    """Use only in the authenticated M6 backend; never ship its key to a browser."""
    def __init__(self, transport, key, agent_id, principal, *, issuer='m6-backend', clock=utc_now):
        self.transport, self.key, self.agent_id = transport, key, agent_id
        self.principal, self.issuer, self.clock = deepcopy(principal), issuer, clock
        signed({}, key)

    def call(self, method, **params):
        now = self.clock()
        packet = signed({'version': 1, 'issuer': self.issuer, 'agent_id': self.agent_id,
                         'request_id': str(uuid.uuid4()), 'sent_at': timestamp(now),
                         'expires_at': timestamp(now + dt.timedelta(seconds=60)),
                         'principal': self.principal, 'method': method, 'params': params}, self.key)
        message = canonical(packet)
        if len(message.encode()) > MAX_REQUEST:
            raise GatewayError('bad_request', 'Gateway request exceeds 64 KiB')
        response = json.loads(self.transport(message))
        verify_signature(response, self.key)
        if response.get('request_id') != packet['request_id'] or response.get('agent_id') != self.agent_id:
            raise GatewayError('unauthenticated', 'Gateway response does not match this request')
        if response.get('ok') is not True:
            raise GatewayError(response['error']['code'], response['error']['message'])
        return response['result']

    def action_id(self, idempotency_key):
        return request_identity(self.agent_id, self.principal, idempotency_key)

    def list_cases(self, **page):
        return self.call('list_cases', **page)

    def get_case(self, case_id, **page):
        return self.call('get_case', case_id=case_id, **page)

    def timeline(self, case_id, **page):
        return self.call('timeline', case_id=case_id, **page)

    def risk_decisions(self, case_id, **page):
        return self.call('risk_decisions', case_id=case_id, **page)

    def request_action(self, case_id, action, **params):
        return self.call('request_action', case_id=case_id, action=action, **params)

    def get_action(self, request_id):
        return self.call('get_action', request_id=request_id)

    def outbox(self, limit=100):
        return self.call('outbox', limit=limit)

    def acknowledge(self, event_ids):
        return self.call('acknowledge', event_ids=event_ids)


def load_key(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('Endpoint gateway key must be a root-owned private regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            key = stream.read(4097)
        if not 32 <= len(key) <= 4096:
            raise ValueError('Invalid gateway key length')
        return key
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/ai-rdr/config.json')
    args = parser.parse_args()
    try:
        from ai_rdr_common import Runtime
        runtime = Runtime(json.loads(Path(args.config).read_text()))
        runtime.require_root()
        settings = runtime.config.get('m6_gateway', {})
        if settings.get('enabled') is not True:
            raise GatewayError('disabled', 'M6 gateway is disabled')
        gateway = M6Gateway(runtime, load_key(settings['key_file']))
        line = sys.stdin.readline(MAX_REQUEST + 2)
        if not line.endswith('\n') or len(line.encode()) > MAX_REQUEST:
            raise GatewayError('bad_request', 'Expected one bounded newline-delimited JSON request')
        response = gateway.handle(json.loads(line))
        print(canonical(response))
        return 0 if response['ok'] else 1
    except Exception:
        print(canonical({'ok': False, 'error': {'code': 'unavailable', 'message': 'Gateway unavailable or invalid input'}}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

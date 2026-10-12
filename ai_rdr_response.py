#!/usr/bin/env python3
"""Wazuh newline JSON adapter and privileged local analyst/worker CLI."""
import argparse
import json
import select
import sys
import time
import os
import uuid

from ai_rdr_common import Runtime
from ai_rdr_actions import Actions
from freeze_verify_manager import Workflow
from ai_rdr_aicm import encode, text_id, correlate_case


def read_message(stream, timeout=5):
    if stream is sys.stdin and not select.select([stream], [], [], timeout)[0]:
        raise TimeoutError('Wazuh protocol read deadline exceeded')
    line = stream.readline(65537)
    if not line or len(line) > 65536 or not line.endswith('\n'):
        raise ValueError('Expected bounded newline-delimited JSON message')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('Expected JSON object')
    return value


def wazuh(runtime, action, incoming=sys.stdin, outgoing=sys.stdout):
    runtime.request_id = str(uuid.uuid4())
    runtime.request_started = False
    payload = None
    try:
        payload = read_message(incoming)
        return _wazuh(runtime, action, payload, incoming, outgoing)
    except Exception as exc:
        case_id = None
        if isinstance(payload, dict):
            parameters = payload.get('parameters')
            alert = parameters.get('alert') if isinstance(parameters, dict) else None
            data = alert.get('data') if isinstance(alert, dict) else None
            if isinstance(data, dict):
                candidate = data.get('case_id')
                if isinstance(candidate, str) and 0 < len(candidate) <= 128 and not any(ord(c) < 32 for c in candidate):
                    case_id = candidate
        event_type = 'response.request_failed' if runtime.request_started else 'response.request_rejected'
        runtime.store.append_event(case_id, event_type, actor=runtime.actor,
                                   request_id=runtime.request_id, outcome='failure',
                                   details={'action': action, 'error_type': type(exc).__name__})
        raise


def _wazuh(runtime, action, payload, incoming, outgoing):
    command = payload.get('command')
    if command not in ('add', 'delete'):
        raise ValueError('Expected add/delete')
    data = payload['parameters']['alert']['data']
    alert = payload['parameters']['alert']
    agent_id = str(alert.get('agent', {}).get('id', runtime.config.get('agent_id', 'local')))
    source_id = alert.get('id') or data.get('alert_id')
    case_id = data.get('case_id')
    if case_id is None:
        process = ({k: data[k] for k in ('pid', 'start_ticks', 'boot_id')}
                   if all(k in data for k in ('pid', 'start_ticks', 'boot_id')) else None)
        case_id = correlate_case(agent_id=agent_id, producer='wazuh',
                                 source_id=str(source_id) if source_id is not None else None,
                                 process=process)
    if not isinstance(case_id, str) or not case_id or len(case_id) > 128:
        raise ValueError('Explicit Case ID required')
    text_id(case_id, 'Case ID')
    if runtime.config.get('agent_id') and agent_id != runtime.config['agent_id']:
        raise ValueError('Alert agent identity differs from endpoint configuration')
    operation_id = None
    if action in ('freeze', 'kill'):
        identity_key = [case_id, agent_id, data.get('pid'), data.get('start_ticks'), data.get('boot_id')]
        operation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, encode(identity_key)))
    target = {'isolate': 'host', 'block': data.get('src_ip'),
              'disable': data.get('username'), 'freeze': data.get('pid'),
              'kill': data.get('pid')}[action]
    if target is None:
        raise ValueError('Missing action target')
    if action == 'kill' and command == 'delete':
        raise ValueError('Kill is irreversible')
    if command == 'add':
        # Include case and identity so independent cases get independent leases.
        key = json.dumps([action, case_id, target, data.get('start_ticks'), data.get('boot_id')])
        outgoing.write(json.dumps({'version': 1, 'origin': {'name': 'ai-rdr', 'module': 'active-response'},
                                   'command': 'check_keys', 'parameters': {'keys': [key]}}) + '\n')
        outgoing.flush()
        reply = read_message(incoming)
        if reply.get('command') == 'abort':
            runtime.store.append_event(case_id, 'response.duplicate_suppressed', actor=runtime.actor,
                                       request_id=runtime.request_id, operation_id=operation_id,
                                       details={'action': action})
            return
        if reply.get('command') != 'continue':
            raise ValueError('Invalid check_keys reply')
    if source_id is not None:
        runtime.store.attach_alert(case_id, producer='wazuh', agent_id=agent_id,
                                   source_id=str(source_id), occurred_at=alert['timestamp'],
                                   metadata={'rule': alert.get('rule', {}),
                                             'risk_score': data.get('risk_score'),
                                             'model_version': data.get('model_version'),
                                             'pid': data.get('pid'), 'start_ticks': data.get('start_ticks'),
                                             'boot_id': data.get('boot_id'), 'evidence': data.get('evidence')},
                                   actor=runtime.actor, request_id=runtime.request_id)
    evidence = data.get('evidence')
    if isinstance(evidence, dict) and evidence.get('event_id'):
        runtime.store.attach_evidence(case_id,
            evidence_id=str(uuid.uuid5(uuid.NAMESPACE_URL, encode([case_id, agent_id, evidence['event_id']]))),
            kind=evidence['type'], reference='wazuh:' + agent_id + ':' + str(evidence['event_id']),
            metadata=evidence, actor=runtime.actor)
    with runtime.transaction() as state:
        if action in ('freeze', 'kill') and case_id in state['cases']:
            # Existing one-root cases retain their operation and lease identifiers.
            operation_id = case_id
        runtime.store.append_event(case_id, 'response.requested', actor=runtime.actor,
                                   request_id=runtime.request_id, operation_id=operation_id,
                                   phase='requested', outcome='unknown',
                                   details={'action': action, 'command': command, 'target': target,
                                            'agent_id': agent_id, 'alert_recorded': source_id is not None})
        state['policy'] = {'version': runtime.config.get('policy_version', 'candidate-v1'),
                           'verification_seconds': runtime.config.get('verification_seconds'),
                           'timeout_policy': runtime.config.get('timeout_policy')}
        workflow = Workflow(runtime)
        runtime.request_started = True
        if action in ('isolate', 'block', 'disable'):
            Actions(runtime).reversible(state, action, target, case_id, command == 'add')
        elif command == 'delete':
            if operation_id in state['cases']:
                workflow.thaw(state, case_id, 'wazuh_timeout', operation_id=operation_id)
            elif case_id in state['cases']:
                workflow.thaw(state, case_id, 'wazuh_timeout')  # Pre-AICM timer.
        else:
            if action == 'kill':
                candidate = dict(state['cases'].get(operation_id, state['cases'].get(case_id, {})))
                if not candidate:
                    candidate = {'root': runtime.identity(int(target))}
                if data.get('evidence'):
                    candidate['evidence'] = data['evidence']
                if not workflow.confirmed(candidate):
                    raise ValueError('Kill requires positive evidence or prior analyst approval')
            workflow.freeze(state, case_id, int(target), data['start_ticks'], data['boot_id'],
                            data['risk_score'], data.get('evidence'), operation_id=operation_id)
            if action == 'kill':
                workflow.contain(state, case_id, operation_id=operation_id)
            else:
                workflow.tick(state)


def main(default_action=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config')
    sub = parser.add_subparsers(dest='mode')
    ar = sub.add_parser('wazuh')
    ar.add_argument('action', choices=['freeze', 'kill', 'isolate', 'block', 'disable'])
    sub.add_parser('worker')
    sub.add_parser('status')
    for name in ('approve', 'thaw', 'undo'):
        item = sub.add_parser(name)
        item.add_argument('case_id')
        item.add_argument('--reason', required=True)
        if name != 'undo':
            item.add_argument('--operation', help='Process operation ID; required if several are active')
    args = parser.parse_args()
    runtime = None
    try:
        if args.config:
            from pathlib import Path
            runtime = Runtime(json.loads(Path(args.config).read_text()))
        else:
            runtime = Runtime()
        runtime.require_root()
        if args.mode == 'wazuh' or (args.mode is None and default_action):
            wazuh(runtime, default_action if args.mode is None else args.action)
        elif args.mode == 'worker':
            while True:
                with runtime.transaction() as state:
                    Workflow(runtime).tick(state)
                time.sleep(0.1)
        elif args.mode == 'status':
            with runtime.transaction() as state:
                print(json.dumps(state, indent=2))
        elif args.mode in ('approve', 'thaw', 'undo'):
            runtime.actor = {'type': 'local_user', 'id': 'unix-uid:' + str(os.getuid())}
            runtime.request_id = str(uuid.uuid4())
            with runtime.transaction() as state:
                workflow = Workflow(runtime)
                if args.mode == 'approve':
                    key = workflow.operation_key(state, args.case_id, args.operation)
                    record = state['cases'][key]
                    if record['status'] not in ('FROZEN', 'REVIEW'):
                        raise ValueError('Case cannot be approved in its current state')
                    record['analyst_approved'] = True
                    record['approval_reason'] = args.reason
                    runtime.save(state)
                    runtime.audit('approve', args.case_id, 'APPROVED', operation_id=key, reason=args.reason)
                    workflow.contain(state, args.case_id, operation_id=key)
                elif args.mode == 'thaw':
                    workflow.thaw(state, args.case_id, args.reason, operation_id=args.operation)
                else:
                    for record in list(state['resources'].values()):
                        if args.case_id in record['owners']:
                            Actions(runtime).reversible(state, record['kind'], record['target'],
                                                        args.case_id, False)
                    runtime.audit('undo', args.case_id, 'SUCCESS', reason=args.reason)
        else:
            parser.error('Choose a mode')
        return 0
    except Exception as exc:
        if runtime is not None and args.mode in ('approve', 'thaw', 'undo'):
            runtime.store.append_event(args.case_id, 'response.analyst_request_failed', actor=runtime.actor,
                                       request_id=runtime.request_id, outcome='failure',
                                       details={'action': args.mode, 'reason': args.reason,
                                                'error_type': type(exc).__name__})
        print(f'AI-RDR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Wazuh newline JSON adapter and privileged local analyst/worker CLI."""
import argparse
import json
import select
import sys
import time

from ai_rdr_common import Runtime
from ai_rdr_actions import Actions
from freeze_verify_manager import Workflow


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
    payload = read_message(incoming)
    command = payload.get('command')
    if command not in ('add', 'delete'):
        raise ValueError('Expected add/delete')
    data = payload['parameters']['alert']['data']
    case_id = data['case_id']
    if not isinstance(case_id, str) or not case_id or len(case_id) > 128:
        raise ValueError('Explicit Case ID required')
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
            return
        if reply.get('command') != 'continue':
            raise ValueError('Invalid check_keys reply')
    with runtime.transaction() as state:
        workflow = Workflow(runtime)
        if action in ('isolate', 'block', 'disable'):
            Actions(runtime).reversible(state, action, target, case_id, command == 'add')
        elif command == 'delete':
            if case_id in state['cases']:
                workflow.thaw(state, case_id, 'wazuh_timeout')
        else:
            if action == 'kill':
                candidate = dict(state['cases'].get(case_id, {}))
                if not candidate:
                    candidate = {'root': runtime.identity(int(target))}
                if data.get('evidence'):
                    candidate['evidence'] = data['evidence']
                if not workflow.confirmed(candidate):
                    raise ValueError('Kill requires positive evidence or prior analyst approval')
            workflow.freeze(state, case_id, int(target), data['start_ticks'], data['boot_id'],
                            data['risk_score'], data.get('evidence'))
            if action == 'kill':
                workflow.contain(state, case_id)
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
    args = parser.parse_args()
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
            with runtime.transaction() as state:
                workflow = Workflow(runtime)
                if args.mode == 'approve':
                    record = state['cases'][args.case_id]
                    if record['status'] not in ('FROZEN', 'REVIEW'):
                        raise ValueError('Case cannot be approved in its current state')
                    record['analyst_approved'] = True
                    runtime.save(state)
                    runtime.audit('approve', args.case_id, 'APPROVED', reason=args.reason)
                    workflow.contain(state, args.case_id)
                elif args.mode == 'thaw':
                    workflow.thaw(state, args.case_id, args.reason)
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
        print(f'AI-RDR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

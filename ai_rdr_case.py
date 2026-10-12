#!/usr/bin/env python3
"""Local AICM CLI. File permissions authorise access; no remote API is exposed."""
import argparse
import json
import os
import sys

from ai_rdr_aicm import CaseStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', default='/var/lib/ai-rdr/aicm.sqlite3')
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--title', required=True)
    create.add_argument('--case-id')
    create.add_argument('--severity', default='medium')
    listing = commands.add_parser('list')
    listing.add_argument('--limit', type=int, default=100)
    listing.add_argument('--offset', type=int, default=0)
    for command in ('show', 'export'):
        commands.add_parser(command).add_argument('case_id')
    timeline = commands.add_parser('timeline')
    timeline.add_argument('case_id', help='Use - for case-independent security events')
    timeline.add_argument('--after', type=int, default=0)
    timeline.add_argument('--limit', type=int, default=100)
    update = commands.add_parser('update')
    update.add_argument('case_id')
    update.add_argument('--version', required=True, type=int)
    update.add_argument('--reason', required=True)
    for field in ('title', 'severity', 'lifecycle', 'disposition', 'assignee', 'duplicate_of'):
        update.add_argument('--' + field.replace('_', '-'))
    note = commands.add_parser('note')
    note.add_argument('case_id')
    note.add_argument('--text', required=True)
    outbox = commands.add_parser('outbox')
    outbox.add_argument('--limit', type=int, default=100)
    commands.add_parser('backup').add_argument('destination')
    args = parser.parse_args()
    actor = {'type': 'local_user', 'id': 'unix-uid:' + str(os.getuid())}
    try:
        store = CaseStore(args.database)
        if args.command == 'create':
            result = store.create_case(actor=actor, title=args.title, severity=args.severity, case_id=args.case_id)
        elif args.command == 'list':
            result = store.list_cases(args.limit, args.offset)
        elif args.command == 'show':
            result = store.get_case(args.case_id)
        elif args.command == 'export':
            store.append_event(args.case_id, 'case.export_requested', actor=actor)
            result = store.export_case(args.case_id)
        elif args.command == 'timeline':
            result = store.timeline(None if args.case_id == '-' else args.case_id, args.after, args.limit)
        elif args.command == 'update':
            changes = {key: getattr(args, key) for key in
                       ('title', 'severity', 'lifecycle', 'disposition', 'assignee', 'duplicate_of')
                       if getattr(args, key) is not None}
            result = store.update_case(args.case_id, actor=actor, expected_version=args.version,
                                       reason=args.reason, **changes)
        elif args.command == 'note':
            result = store.append_event(args.case_id, 'case.note_added', actor=actor,
                                        details={'text': args.text})
        elif args.command == 'outbox':
            result = store.pending_events(args.limit)
        else:
            store.backup(args.destination)
            store.append_event(None, 'database.backup_completed', actor=actor)
            result = {'backup': args.destination}
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f'AICM: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

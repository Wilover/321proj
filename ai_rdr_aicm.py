"""AI-RDR incident cases and durable audit journal (stdlib SQLite, schema v1).

Application-level append-only records; not a defence against a root compromise.
Callers are trusted local components. M6 must authenticate remote callers before
constructing actor identities or invoking this module.
"""
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid


SCHEMA_VERSION = 1
TERMINAL = {'THAWED', 'KILLED', 'FAILED', 'STALE_BOOT'}
LIFECYCLES = {
    'open': {'investigating', 'resolved'},
    'investigating': {'resolved'},
    'resolved': {'closed', 'investigating'},
    'closed': {'investigating'},
}
DISPOSITIONS = {'undetermined', 'malicious', 'benign', 'duplicate'}
SEVERITIES = {'low', 'medium', 'high', 'critical'}
SECRET_KEY = re.compile(r'password|passwd|secret|token|authorization|credential|shadow', re.I)


class Conflict(ValueError):
    """An identifier, version, or requested transition conflicts with stored state."""


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def text_id(value, name='identifier'):
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f'Invalid {name}')
    if any(ord(c) < 32 for c in value):
        raise ValueError(f'Control character in {name}')
    return value


def timestamp(value):
    text_id(value, 'timestamp')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp must include a timezone')
    return parsed.astimezone(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def redact(value, depth=0):
    if depth > 12:
        raise ValueError('Metadata nesting exceeds limit')
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SECRET_KEY.search(str(k)) else redact(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    return value


def encode(value):
    result = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if len(result.encode()) > 1024 * 1024:
        raise ValueError('Record exceeds 1 MiB')
    return result


def actor_identity(actor):
    if not isinstance(actor, dict) or actor.get('type') not in ('service', 'local_user', 'user'):
        raise ValueError('Explicit actor type and identity required')
    text_id(actor.get('id'), 'actor ID')
    # Actor metadata comes from the caller's authenticated context, not alert JSON.
    return {k: actor[k] for k in ('type', 'id')}


def correlate_case(*, agent_id, producer, source_id=None, process=None):
    """Conservative deterministic case ID for a local fast path.

    Prefer immutable process identity; otherwise group only the same source alert.
    Explicit caller-supplied Case IDs remain necessary for multi-root incidents.
    """
    text_id(agent_id, 'agent ID')
    text_id(producer, 'producer')
    if process is not None:
        pid, ticks = int(process['pid']), int(process['start_ticks'])
        text_id(process['boot_id'], 'boot ID')
        if pid <= 1 or ticks < 0:
            raise ValueError('Invalid process correlation identity')
        key = ['ai-rdr:process', agent_id, process['boot_id'], pid, ticks]
    else:
        text_id(source_id, 'source alert ID')
        key = ['ai-rdr:alert', producer, agent_id, source_id]
    return str(uuid.uuid5(uuid.NAMESPACE_URL, encode(key)))


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
 case_id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
 lifecycle TEXT NOT NULL, disposition TEXT NOT NULL, assignee TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT,
 closure_reason TEXT, duplicate_of TEXT REFERENCES cases(case_id),
 version INTEGER NOT NULL, last_sequence INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
 alert_key TEXT PRIMARY KEY, producer TEXT NOT NULL, agent_id TEXT NOT NULL,
 source_id TEXT NOT NULL, occurred_at TEXT NOT NULL, recorded_at TEXT NOT NULL,
 metadata TEXT NOT NULL, fingerprint TEXT NOT NULL,
 UNIQUE(producer,agent_id,source_id)
);
CREATE TABLE IF NOT EXISTS case_alerts (
 case_id TEXT NOT NULL REFERENCES cases(case_id),
 alert_key TEXT NOT NULL REFERENCES alerts(alert_key),
 PRIMARY KEY(case_id,alert_key)
);
CREATE TABLE IF NOT EXISTS evidence (
 evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
 reference TEXT NOT NULL, kind TEXT NOT NULL, metadata TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
 operation_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
 kind TEXT NOT NULL, status TEXT NOT NULL, target TEXT NOT NULL,
 details TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS operations_case ON operations(case_id);
CREATE TABLE IF NOT EXISTS audit_events (
 event_id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases(case_id),
 sequence INTEGER NOT NULL, event_type TEXT NOT NULL,
 recorded_at TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(case_id,sequence)
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
 BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
 BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
CREATE TABLE IF NOT EXISTS outbox (
 event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id), acknowledged_at TEXT
);
CREATE TABLE IF NOT EXISTS inbox (
 event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id), fingerprint TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), snapshot TEXT NOT NULL
);
"""


class CaseStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Prevent SQLite from initially creating an overly permissive file.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            fd = None
        if fd is not None:
            os.close(fd)
        with self.connection() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise RuntimeError(f'Unsupported database schema {version}')
            if version == 0:
                db.execute('PRAGMA journal_mode=WAL')
                db.executescript('BEGIN IMMEDIATE;\n' + SCHEMA +
                                 f'\nPRAGMA user_version={SCHEMA_VERSION};\nCOMMIT;')

    @contextlib.contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA busy_timeout=5000')
            yield db
        finally:
            db.close()

    @contextlib.contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _event(self, db, case_id, event_type, actor, *, request_id=None,
               operation_id=None, phase='completed', outcome='success', details=None,
               occurred_at=None, event_id=None):
        actor = actor_identity(actor)
        text_id(event_type, 'event type')
        for value in (request_id, operation_id, event_id):
            if value is not None:
                text_id(value)
        if phase not in ('requested', 'started', 'completed', 'rejected', 'reconciled'):
            raise ValueError('Invalid event phase')
        if outcome not in ('success', 'failure', 'unknown'):
            raise ValueError('Invalid outcome')
        now = utc_now()
        if case_id is None:
            sequence = db.execute('SELECT COALESCE(MAX(sequence),0)+1 FROM audit_events WHERE case_id IS NULL').fetchone()[0]
        else:
            row = db.execute('SELECT last_sequence FROM cases WHERE case_id=?', (case_id,)).fetchone()
            if row is None:
                raise KeyError(case_id)
            sequence = row['last_sequence'] + 1
        event = {'schema_version': 1, 'event_id': event_id or str(uuid.uuid4()),
                 'case_id': case_id, 'case_sequence': sequence, 'event_type': event_type,
                 'actor': actor, 'request_id': request_id, 'operation_id': operation_id,
                 'phase': phase, 'outcome': outcome, 'occurred_at': timestamp(occurred_at) if occurred_at else now,
                 'recorded_at': now, 'details': redact(details or {})}
        db.execute('INSERT INTO audit_events VALUES(?,?,?,?,?,?)',
                   (event['event_id'], case_id, sequence, event_type, now, encode(event)))
        db.execute('UPDATE cases SET last_sequence=?,updated_at=? WHERE case_id=?',
                   (sequence, now, case_id))
        db.execute('INSERT INTO outbox(event_id) VALUES(?)', (event['event_id'],))
        return event

    def _ensure_case(self, db, case_id, actor, title=None, severity='medium'):
        text_id(case_id, 'Case ID')
        if db.execute('SELECT 1 FROM cases WHERE case_id=?', (case_id,)).fetchone():
            return False
        if severity not in SEVERITIES:
            raise ValueError('Invalid severity')
        now = utc_now()
        db.execute('''INSERT INTO cases(case_id,title,severity,lifecycle,disposition,
                   created_at,updated_at,version) VALUES(?,?,?,'open','undetermined',?,?,1)''',
                   (case_id, title or f'AI-RDR incident {case_id}', severity, now, now))
        self._event(db, case_id, 'case.created', actor,
                    details={'title': title or f'AI-RDR incident {case_id}', 'severity': severity})
        return True

    def create_case(self, *, actor, title, severity='medium', case_id=None):
        text_id(title, 'title')
        case_id = case_id or str(uuid.uuid4())
        with self.transaction() as db:
            if not self._ensure_case(db, case_id, actor, title, severity):
                raise Conflict('Case already exists')
        return self.get_case(case_id)

    def get_case(self, case_id):
        with self.connection() as db:
            db.execute('BEGIN')
            row = db.execute('SELECT * FROM cases WHERE case_id=?', (case_id,)).fetchone()
            if row is None:
                raise KeyError(case_id)
            result = dict(row)
            result['alerts'] = [json.loads(x['metadata']) | {'alert_key': x['alert_key'],
                                  'producer': x['producer'], 'agent_id': x['agent_id'],
                                  'source_id': x['source_id'], 'occurred_at': x['occurred_at'],
                                  'recorded_at': x['recorded_at']}
                                for x in db.execute('''SELECT a.* FROM alerts a JOIN case_alerts ca
                                  ON ca.alert_key=a.alert_key WHERE ca.case_id=? ORDER BY a.recorded_at''', (case_id,))]
            result['operations'] = [dict(x) | {'target': json.loads(x['target']),
                                                'details': json.loads(x['details'])}
                                    for x in db.execute('SELECT * FROM operations WHERE case_id=? ORDER BY operation_id', (case_id,))]
            result['evidence'] = [dict(x) | {'metadata': json.loads(x['metadata'])}
                                  for x in db.execute('SELECT * FROM evidence WHERE case_id=?', (case_id,))]
            return result

    def list_cases(self, limit=100, offset=0):
        self._page(limit, offset)
        with self.connection() as db:
            return [dict(x) for x in db.execute('SELECT * FROM cases ORDER BY created_at,case_id LIMIT ? OFFSET ?',
                                                (limit, offset))]

    @staticmethod
    def _page(limit, offset):
        if not isinstance(limit, int) or not 1 <= limit <= 1000 or not isinstance(offset, int) or offset < 0:
            raise ValueError('Invalid pagination')

    def timeline(self, case_id, after=0, limit=100):
        self._page(limit, after)
        with self.connection() as db:
            return [json.loads(x[0]) for x in db.execute('''SELECT payload FROM audit_events
                        WHERE case_id IS ? AND sequence>? ORDER BY sequence LIMIT ?''', (case_id, after, limit))]

    def update_case(self, case_id, *, actor, expected_version, reason, **changes):
        actor = actor_identity(actor)
        text_id(reason, 'reason')
        allowed = {'title', 'severity', 'lifecycle', 'disposition', 'assignee', 'duplicate_of'}
        if not changes or set(changes) - allowed:
            raise ValueError('Unsupported case changes')
        with self.transaction() as db:
            row = db.execute('SELECT * FROM cases WHERE case_id=?', (case_id,)).fetchone()
            if row is None:
                raise KeyError(case_id)
            before = dict(row)
            try:
                if before['version'] != expected_version:
                    raise Conflict('Stale case version')
                after = before | changes
                if after['severity'] not in SEVERITIES or after['disposition'] not in DISPOSITIONS:
                    raise ValueError('Invalid severity or disposition')
                text_id(after['title'], 'title')
                if after['assignee'] is not None:
                    text_id(after['assignee'], 'assignee')
                if (after['lifecycle'] != before['lifecycle'] and
                        after['lifecycle'] not in LIFECYCLES.get(before['lifecycle'], set())):
                    raise Conflict('Invalid lifecycle transition')
                if before['lifecycle'] == 'closed' and after['lifecycle'] != 'investigating':
                    raise Conflict('Reopen a closed case before editing it')
                if after['disposition'] == 'duplicate':
                    target = after['duplicate_of']
                    target_row = db.execute('SELECT disposition FROM cases WHERE case_id=?', (target,)).fetchone()
                    if target == case_id or target_row is None or target_row['disposition'] == 'duplicate':
                        raise Conflict('Duplicate must reference an existing canonical case')
                elif after['duplicate_of'] is not None:
                    raise Conflict('Only duplicate cases may reference another case')
                if after['lifecycle'] == 'closed':
                    active = db.execute('SELECT 1 FROM operations WHERE case_id=? AND status NOT IN '
                                        "('THAWED','KILLED','FAILED','STALE_BOOT','REMOVED') LIMIT 1", (case_id,)).fetchone()
                    if active:
                        raise Conflict('Resolve active response operations/leases before closure')
                changed = {k: {'before': before[k], 'after': after[k]} for k in changes if before[k] != after[k]}
            except (ValueError, Conflict) as exc:
                self._event(db, case_id, 'case.update_rejected', actor, outcome='failure',
                            details={'reason': reason, 'error': str(exc)})
                # Commit the rejection without changing the case, then raise below.
                error = exc
            else:
                error = None
                if changed:
                    closed_at = utc_now() if after['lifecycle'] == 'closed' else None
                    db.execute('''UPDATE cases SET title=?,severity=?,lifecycle=?,disposition=?,assignee=?,
                               duplicate_of=?,closed_at=?,closure_reason=?,version=version+1 WHERE case_id=?''',
                               (after['title'], after['severity'], after['lifecycle'], after['disposition'],
                                after['assignee'], after['duplicate_of'], closed_at,
                                reason if closed_at else None, case_id))
                    self._event(db, case_id, 'case.updated', actor, details={'reason': reason, 'changes': changed})
        if error:
            raise error
        return self.get_case(case_id)

    def attach_alert(self, case_id, *, producer, agent_id, source_id, occurred_at,
                     metadata, actor, request_id=None):
        if not isinstance(metadata, dict):
            raise ValueError('Alert metadata must be an object')
        for value in (producer, agent_id, source_id):
            text_id(value)
        when = timestamp(occurred_at)
        body = encode(redact(metadata))
        key = str(uuid.uuid5(uuid.NAMESPACE_URL, encode([producer, agent_id, source_id])))
        fingerprint = hashlib.sha256(encode([when, json.loads(body)]).encode()).hexdigest()
        with self.transaction() as db:
            self._ensure_case(db, case_id, actor)
            existing = db.execute('SELECT fingerprint FROM alerts WHERE alert_key=?', (key,)).fetchone()
            if existing and existing['fingerprint'] != fingerprint:
                raise Conflict('Source alert ID reused with changed content')
            if not existing:
                db.execute('INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?)',
                           (key, producer, agent_id, source_id, when, utc_now(), body, fingerprint))
            added = db.execute('INSERT OR IGNORE INTO case_alerts VALUES(?,?)', (case_id, key)).rowcount
            if added:
                self._event(db, case_id, 'alert.attached', actor, request_id=request_id,
                            occurred_at=when, details={'alert_key': key, 'producer': producer,
                                                       'agent_id': agent_id, 'source_id': source_id})
        return key

    def attach_evidence(self, case_id, *, evidence_id, kind, reference, metadata, actor):
        if not isinstance(metadata, dict):
            raise ValueError('Evidence metadata must be an object')
        for item in (evidence_id, kind, reference):
            text_id(item)
        body = encode(redact(metadata))
        with self.transaction() as db:
            self._ensure_case(db, case_id, actor)
            prior = db.execute('SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
            values = (evidence_id, case_id, reference, kind, body)
            if prior:
                if tuple(prior) != values:
                    raise Conflict('Evidence ID reused with changed content')
                return
            db.execute('INSERT INTO evidence VALUES(?,?,?,?,?)', values)
            self._event(db, case_id, 'evidence.attached', actor,
                        details={'evidence_id': evidence_id, 'kind': kind, 'reference': reference})

    def append_event(self, case_id, event_type, *, actor, **attributes):
        with self.transaction() as db:
            if case_id is not None:
                self._ensure_case(db, case_id, actor)
            return self._event(db, case_id, event_type, actor, **attributes)

    def load_state(self):
        with self.connection() as db:
            row = db.execute('SELECT snapshot FROM runtime_state WHERE singleton=1').fetchone()
            return json.loads(row[0]) if row else None

    @staticmethod
    def _operations(state):
        result = {}
        for operation_id, record in state.get('cases', {}).items():
            case_id = record.get('case_id', operation_id)  # Legacy one-root cases.
            result[operation_id] = {'case_id': case_id, 'kind': 'process_tree',
                                    'status': record['status'], 'target': record['root'], 'details': record}
        for key, record in state.get('resources', {}).items():
            for case_id in record['owners']:
                operation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, encode(['lease', case_id, key])))
                result[operation_id] = {'case_id': case_id, 'kind': record['kind'],
                                        'status': record['status'], 'target': record['target'], 'details': record}
        return result

    def save_state(self, state, *, actor, request_id=None):
        """Atomically save ARM state, operation projections, transitions and outbox."""
        snapshot = encode(state)
        current = self._operations(state)
        with self.transaction() as db:
            row = db.execute('SELECT snapshot FROM runtime_state WHERE singleton=1').fetchone()
            old_state = json.loads(row[0]) if row else {'cases': {}, 'resources': {}}
            previous = self._operations(old_state)
            for operation_id in sorted(current.keys() | previous.keys()):
                old = previous.get(operation_id)
                new = current.get(operation_id)
                if old == new:
                    continue
                record = new or dict(old, status='REMOVED')
                case_id = record['case_id']
                self._ensure_case(db, case_id, actor)
                lifecycle = db.execute('SELECT lifecycle FROM cases WHERE case_id=?', (case_id,)).fetchone()[0]
                if lifecycle == 'closed' and new is not None:
                    raise Conflict('Reopen the incident before changing a response operation')
                existing = db.execute('SELECT case_id FROM operations WHERE operation_id=?', (operation_id,)).fetchone()
                if existing and existing['case_id'] != case_id:
                    raise Conflict('Operation cannot change incident ownership')
                db.execute('''INSERT INTO operations VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(operation_id) DO UPDATE SET status=excluded.status,
                    target=excluded.target,details=excluded.details,updated_at=excluded.updated_at''',
                           (operation_id, case_id, record['kind'], record['status'],
                            encode(redact(record['target'])), encode(redact(record['details'])), utc_now()))
                status = record['status']
                phase = 'requested' if status in ('PREPARING', 'PENDING', 'THAWING', 'REMOVING', 'CONTAINING') else 'completed'
                outcome = 'failure' if status in ('FAILED', 'STALE_BOOT') else 'unknown' if phase == 'requested' or status == 'REVIEW' else 'success'
                self._event(db, case_id, 'response.state_changed', actor, request_id=request_id,
                            operation_id=operation_id, phase=phase, outcome=outcome,
                            details={'kind': record['kind'], 'target': record['target'],
                                     'before': old['status'] if old else None, 'after': status,
                                     'policy': state.get('policy', {}),
                                     'reason': record['details'].get('thaw_reason') or record['details'].get('approval_reason'),
                                     'changes': {field: {'before': old['details'].get(field) if old else None,
                                                         'after': record['details'].get(field)}
                                                 for field in ('score', 'evidence', 'analyst_approved', 'approval_reason', 'thaw_reason')
                                                 if (old['details'].get(field) if old else None) != record['details'].get(field)}})
            db.execute('INSERT INTO runtime_state VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET snapshot=excluded.snapshot', (snapshot,))

    def pending_events(self, limit=100):
        self._page(limit, 0)
        with self.connection() as db:
            return [json.loads(x[0]) for x in db.execute('''SELECT a.payload FROM audit_events a
                JOIN outbox o ON o.event_id=a.event_id WHERE o.acknowledged_at IS NULL
                ORDER BY a.case_id,a.sequence LIMIT ?''', (limit,))]

    def acknowledge(self, event_ids):
        """Call only after a durable receiver acknowledgement; never drops audit."""
        with self.transaction() as db:
            for event_id in event_ids:
                changed = db.execute('UPDATE outbox SET acknowledged_at=COALESCE(acknowledged_at,?) WHERE event_id=?',
                                     (utc_now(), event_id)).rowcount
                if not changed:
                    raise KeyError(event_id)

    def ingest_event(self, event, *, received_by):
        """Idempotent import from a TRUSTED endpoint, not an unauthenticated API.

        Preserves origin ID/actor/time and records central sequence separately.
        This imports history, not authoritative OS state or a central case verdict.
        """
        received_by = actor_identity(received_by)
        body = encode(redact(event))
        event = json.loads(body)
        if event.get('schema_version') != 1:
            raise ValueError('Unsupported event schema')
        event_id = text_id(event['event_id'], 'event ID')
        fingerprint = hashlib.sha256(body.encode()).hexdigest()
        with self.transaction() as db:
            prior = db.execute('SELECT fingerprint FROM inbox WHERE event_id=?', (event_id,)).fetchone()
            if prior:
                if prior[0] != fingerprint:
                    raise Conflict('Delivered event ID reused with changed content')
                return False
            case_id = event['case_id']
            if case_id is not None:
                self._ensure_case(db, case_id, received_by)
            details = event.get('details', {}) | {
                'delivery': {'origin_sequence': event.get('case_sequence'),
                             'origin_recorded_at': event['recorded_at'], 'received_by': received_by}}
            self._event(db, case_id, event['event_type'], event['actor'],
                        request_id=event.get('request_id'), operation_id=event.get('operation_id'),
                        phase=event['phase'], outcome=event['outcome'], details=details,
                        occurred_at=event['occurred_at'], event_id=event_id)
            db.execute('INSERT INTO inbox VALUES(?,?)', (event_id, fingerprint))
        return True

    def backup(self, destination):
        """Consistent SQLite backup including WAL commits; never copy a live DB alone."""
        destination = Path(destination)
        if destination.resolve() == self.path.resolve():
            raise ValueError('Backup destination must differ from source')
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with self.connection() as source:
                target = sqlite3.connect(destination)
                try:
                    source.backup(target)
                finally:
                    target.close()
        except BaseException:
            destination.unlink()
            raise

    def export_case(self, case_id):
        # A read transaction gives case + complete audit a consistent snapshot.
        with self.connection() as db:
            db.execute('BEGIN')
            case = db.execute('SELECT * FROM cases WHERE case_id=?', (case_id,)).fetchone()
            if case is None:
                raise KeyError(case_id)
            return {'schema_version': 1, 'exported_at': utc_now(), 'case': dict(case),
                    'alerts': [dict(x) | {'metadata': json.loads(x['metadata'])} for x in db.execute(
                        '''SELECT a.* FROM alerts a JOIN case_alerts ca ON a.alert_key=ca.alert_key
                        WHERE ca.case_id=? ORDER BY a.recorded_at''', (case_id,))],
                    'operations': [dict(x) | {'target': json.loads(x['target']), 'details': json.loads(x['details'])}
                                   for x in db.execute('SELECT * FROM operations WHERE case_id=?', (case_id,))],
                    'evidence': [dict(x) | {'metadata': json.loads(x['metadata'])}
                                 for x in db.execute('SELECT * FROM evidence WHERE case_id=?', (case_id,))],
                    'events': [json.loads(x[0]) for x in db.execute(
                        'SELECT payload FROM audit_events WHERE case_id=? ORDER BY sequence', (case_id,))]}

"""One case state machine shared by the Wazuh adapter and deadline worker."""
import signal
import time

from ai_rdr_actions import Actions


TERMINAL = {'THAWED', 'KILLED', 'FAILED', 'STALE_BOOT'}


class Workflow:
    def __init__(self, runtime):
        self.r = runtime
        self.actions = Actions(runtime)

    def confirmed(self, record):
        # Evidence comes from the trusted detector contract, never file atime.
        evidence = record.get('evidence', {})
        root = record['root']
        return (record.get('analyst_approved', False) or
                (evidence.get('type') == 'decoy_write' and evidence.get('event_id')
                 and evidence.get('pid') == root['pid']
                 and evidence.get('start_ticks') == root['start_ticks']
                 and evidence.get('boot_id') == root['boot_id']))

    def freeze(self, state, case_id, pid, start_ticks, boot_id, score, evidence=None):
        if not isinstance(case_id, str) or not case_id or len(case_id) > 128:
            raise ValueError('Explicit Case ID required')
        if case_id in state['cases']:
            old = state['cases'][case_id]
            if (old['root']['pid'] != int(pid) or old['root']['start_ticks'] != int(start_ticks)
                    or old['root']['boot_id'] != boot_id):
                raise ValueError('Case ID already belongs to another process')
            if evidence and old['status'] not in TERMINAL:
                candidate = dict(old, evidence=evidence)
                if not self.confirmed(candidate):
                    raise ValueError('New evidence does not identify the case process')
                old['evidence'] = evidence
                self.r.save(state)
            return old
        root = self.r.identity(pid)
        if root['start_ticks'] != int(start_ticks) or root['boot_id'] != boot_id:
            raise ValueError('Stale alert process identity')
        if self.r.protected(root):
            raise ValueError('Protected process')
        record = {'root': root, 'processes': [], 'status': 'PREPARING',
                  'score': float(score), 'created_monotonic': time.monotonic(),
                  'boot_id': self.r.boot_id(), 'evidence': evidence or {}}
        if not 0.60 <= float(score) < 0.90 and not self.confirmed(record):
            raise ValueError('Outside candidate freeze range without confirming evidence')
        window = float(self.r.config['verification_seconds'])
        if not 0 < window <= 10:
            raise ValueError('verification_seconds must be in (0, 10]')
        if self.r.config['timeout_policy'] not in ('thaw', 'review'):
            raise ValueError('Choose explicit timeout_policy: thaw or review')
        record['deadline'] = record['created_monotonic'] + window
        state['cases'][case_id] = record
        self.r.save(state)
        try:
            queue = [root]
            seen = set()
            while queue:
                identity = queue.pop(0)
                key = (identity['pid'], identity['start_ticks'], identity['boot_id'])
                if key in seen:
                    continue
                seen.add(key)
                if len(seen) > 128 or time.monotonic() - record['created_monotonic'] > 2:
                    raise RuntimeError('Process-tree freeze budget exceeded')
                if self.r.protected(identity):
                    raise ValueError('Protected descendant')
                for other_id, other in state['cases'].items():
                    if other_id == case_id or other['status'] in TERMINAL:
                        continue
                    if any((p['pid'], p['start_ticks'], p['boot_id']) == key
                           for p in other['processes']):
                        raise ValueError('Process already owned by another active case')
                item = dict(identity, ai_rdr_stopped=identity['state'] not in ('T', 't'))
                record['processes'].append(item)
                # Journal intent before sending SIGSTOP for crash recovery.
                self.r.save(state)
                if item['ai_rdr_stopped']:
                    self.r.signal_identity(identity, signal.SIGSTOP)
                if not self.r.wait_effect(identity, stopped=True):
                    raise RuntimeError('Process did not stop')
                # Stop parent before enumerating children; bounds limit hostile fan-out.
                queue.extend(self.r.children(identity['pid']))
            record['status'] = 'FROZEN'
            self.r.save(state)
            self.r.audit('freeze', case_id, 'SUCCESS',
                         elapsed_ms=(time.monotonic() - record['created_monotonic']) * 1000,
                         process_count=len(record['processes']))
        except Exception:
            self.thaw(state, case_id, 'freeze_failed')
            record['status'] = 'FAILED'
            self.r.save(state)
            raise
        return record

    def thaw(self, state, case_id, reason):
        record = state['cases'][case_id]
        if record['status'] in TERMINAL:
            return
        record['status'] = 'THAWING'
        record['thaw_reason'] = reason
        self.r.save(state)
        errors = []
        for item in reversed(record['processes']):
            if not item['ai_rdr_stopped']:
                continue
            try:
                self.r.signal_identity(item, signal.SIGCONT)
                if not self.r.wait_resumed(item):
                    raise RuntimeError('Process did not resume')
            except (FileNotFoundError, ProcessLookupError):
                continue
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            self.r.audit('thaw', case_id, 'PARTIAL', errors=errors)
            raise RuntimeError('Thaw incomplete; state retained for retry')
        # Thaw only resumes processes. Network undo is an independent, explicit action.
        record['status'] = 'THAWED'
        self.r.save(state)
        self.r.audit('thaw', case_id, 'SUCCESS', reason=reason,
                     frozen_seconds=time.monotonic() - record['created_monotonic'])

    def contain(self, state, case_id, isolate=True):
        record = state['cases'][case_id]
        if record['status'] == 'KILLED':
            return
        if record['status'] not in ('FROZEN', 'REVIEW', 'CONTAINING'):
            raise ValueError('Case is not eligible for containment')
        if self.r.config.get('critical_asset', False) and not record.get('analyst_approved'):
            raise ValueError('Critical asset requires explicit analyst approval')
        if not self.confirmed(record):
            raise ValueError('Positive evidence or analyst approval required')
        record['status'] = 'CONTAINING'
        record['isolate_requested'] = isolate
        self.r.save(state)
        # Persist isolation first; a failed kill must not undo completed isolation.
        if isolate:
            self.actions.reversible(state, 'isolate', 'host', case_id, True)
        self.actions.kill(record['processes'], case_id)
        record['status'] = 'KILLED'
        self.r.save(state)

    def tick(self, state):
        self.actions.reconcile(state)
        for case_id, record in list(state['cases'].items()):
            if record['status'] in TERMINAL:
                continue
            try:
                if record['boot_id'] != self.r.boot_id():
                    record['status'] = 'STALE_BOOT'
                    self.r.save(state)
                    self.r.audit('recovery', case_id, 'STALE_BOOT')
                elif record['status'] in ('PREPARING', 'THAWING'):
                    self.thaw(state, case_id, record.get('thaw_reason', 'interrupted_freeze'))
                elif record['status'] == 'CONTAINING':
                    self.contain(state, case_id, record.get('isolate_requested', True))
                elif self.confirmed(record) and (not self.r.config.get('critical_asset', False)
                                                or record.get('analyst_approved')):
                    self.contain(state, case_id)
                elif time.monotonic() >= record['deadline'] and record['status'] != 'REVIEW':
                    if self.r.config['timeout_policy'] == 'thaw' and not self.confirmed(record):
                        self.thaw(state, case_id, 'inconclusive_timeout')
                    else:
                        record['status'] = 'REVIEW'
                        self.r.save(state)
                        self.r.audit('verify', case_id, 'REVIEW_REQUIRED',
                                     reason='critical_asset' if self.confirmed(record) else 'inconclusive_timeout')
            except Exception as exc:
                self.r.audit('workflow', case_id, 'FAILED', error=str(exc))

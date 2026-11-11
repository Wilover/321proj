#!/usr/bin/env python3
"""Deterministic M5 evidence scoring. No network, database or OS response effects.

Scores are policy priorities, not probabilities. Prototype weights require
scenario calibration. Inputs must come from authenticated upstream adapters;
this module neither attributes inotify events nor discovers a PID from a window.
"""
import argparse
from copy import deepcopy
import datetime as dt
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import sys
import uuid

from ai_rdr_policy import attributed_decoy, process_identity_valid, response_mode


DEFAULT_MATRIX = {
    'version': 'm5-risk-matrix-v1',
    'calibration_status': 'prototype-not-calibrated',
    'bands': {'suspicious': 30, 'high': 70},
    'weights': {'ml': 55, 'monitoring': 35, 'honeyfile': 55,
                'threat_intel': 55, 'attributed_decoy': 95, 'corroboration': 20},
    'groups': {'ml': 'behaviour', 'monitoring': 'behaviour',
               'honeyfile': 'decoy', 'threat_intel': 'intelligence'},
    'correlation_seconds': 5, 'max_signal_age_seconds': 30,
    'threat_intel_max_age_seconds': 900, 'future_skew_seconds': 30,
    'high_action': 'freeze', 'allow_single_signal': False, 'benign_guards': [],
}
SOURCES = ('ml', 'monitoring', 'honeyfile', 'threat_intel')
PROCESS_KEYS = ('pid', 'start_ticks', 'boot_id')
MODEL_KEYS = ('ransomware_probability', 'threshold', 'prediction', 'alert')


class EvidenceConflict(ValueError):
    pass


def number(value, low=0, high=100):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError('Expected a finite number in [%s, %s]' % (low, high))
    return float(value)


def utc(value):
    if isinstance(value, str):
        value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, dt.datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Timezone-aware timestamp required')
    return value.astimezone(dt.timezone.utc)


def stamp(value):
    return utc(value).isoformat().replace('+00:00', 'Z')


def identity(value):
    if not isinstance(value, dict):
        return None
    present = any(k in value for k in PROCESS_KEYS)
    if not present:
        return None
    if not process_identity_valid(value):
        raise ValueError('Incomplete or untyped process identity')
    return {key: value[key] for key in PROCESS_KEYS}


class RiskMatrix:
    def __init__(self, endpoint_config=None):
        config = {} if endpoint_config is None else endpoint_config
        if not isinstance(config, dict):
            raise ValueError('Endpoint configuration must be an object')
        supplied = config.get('risk_matrix', {})
        if config.get('risk_matrix_file'):
            if supplied:
                raise ValueError('Use risk_matrix or risk_matrix_file, not both')
            supplied = json.loads(Path(config['risk_matrix_file']).read_text())
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULT_MATRIX):
            raise ValueError('Invalid risk matrix configuration')
        self.policy = deepcopy(DEFAULT_MATRIX)
        for key, value in supplied.items():
            if key in ('bands', 'weights', 'groups'):
                if not isinstance(value, dict) or set(value) - set(self.policy[key]):
                    raise ValueError('Invalid matrix ' + key)
                self.policy[key].update(value)
            else:
                self.policy[key] = deepcopy(value)
        p = self.policy
        for key in ('version', 'calibration_status'):
            if not isinstance(p[key], str) or not p[key].strip() or len(p[key]) > 128:
                raise ValueError('Invalid matrix ' + key)
        for value in p['weights'].values():
            number(value)
        if not 0 < number(p['bands']['suspicious']) < number(p['bands']['high']) <= 100:
            raise ValueError('Risk bands must be ordered')
        if p['weights']['attributed_decoy'] < p['bands']['high']:
            raise ValueError('Attributed decoy weight must reach the high band')
        for key in ('correlation_seconds', 'max_signal_age_seconds',
                    'threat_intel_max_age_seconds', 'future_skew_seconds'):
            number(p[key], 0, 86400)
        if p['max_signal_age_seconds'] == 0 or p['threat_intel_max_age_seconds'] == 0:
            raise ValueError('Evidence age limits must be positive')
        if any(not isinstance(x, str) or not x.strip() or len(x) > 128 for x in p['groups'].values()):
            raise ValueError('Invalid evidence group')
        if p['high_action'] not in ('freeze', 'isolate', 'block', 'disable'):
            raise ValueError('High action must be reversible; kill follows Freeze/Verify')
        if type(p['allow_single_signal']) is not bool or not isinstance(p['benign_guards'], list):
            raise ValueError('Invalid matrix controls')
        if len(p['benign_guards']) > 128:
            raise ValueError('Too many benign guards')
        for guard in p['benign_guards']:
            if (not isinstance(guard, dict) or set(guard) - {
                    'id', 'agent_id', 'sha256', 'process_name', 'username', 'expires_at'}
                    or any(not isinstance(guard.get(k), str) or not guard[k].strip()
                           for k in ('id', 'agent_id', 'sha256', 'expires_at'))):
                raise ValueError('Guards require an ID, endpoint, SHA256 and expiry')
            self._hash(guard['sha256'])
            utc(guard['expires_at'])
            for key in ('process_name', 'username'):
                if key in guard and (not isinstance(guard[key], str) or not guard[key]):
                    raise ValueError('Invalid benign guard selector')

    @staticmethod
    def _hash(value):
        if (not isinstance(value, str) or len(value) != 64
                or any(c not in '0123456789abcdefABCDEF' for c in value)):
            raise ValueError('SHA256 must contain 64 hexadecimal characters')
        int(value, 16)
        return value.lower()

    def evaluate(self, data, *, agent_id=None, case_id=None, source_id=None,
                 occurred_at=None, now=None):
        if not isinstance(data, dict):
            raise ValueError('Evidence bundle must be an object')
        # Reject non-JSON/NaN inputs before deriving a replay identity.
        if len(json.dumps(data, allow_nan=False).encode()) > 65536:
            raise ValueError('Evidence bundle exceeds 64 KiB')
        now = utc(now or dt.datetime.now(dt.timezone.utc))
        event_time = utc(occurred_at) if occurred_at else now
        host = agent_id or data.get('agent_id')
        if not isinstance(host, str) or not host.strip():
            raise ValueError('Explicit endpoint identity required')
        if data.get('agent_id', host) != host:
            raise ValueError('Bundle endpoint differs from the Wazuh endpoint')
        target = identity(data)
        p = self.policy
        evidence, seen, errors = [], {}, []
        mode = response_mode(data)

        def add(source, raw, strength, reason, *, process=None, when=None, status='present'):
            if not isinstance(raw, dict):
                raise ValueError(source + ' evidence must be an object')
            endpoint = raw.get('agent_id', host)
            if not isinstance(endpoint, str) or not endpoint:
                raise ValueError('Invalid source endpoint')
            moment = utc(when or raw.get('timestamp') or event_time)
            age = (now - moment).total_seconds()
            if age < -p['future_skew_seconds']:
                status, strength, reason = 'future_timestamp', 0, 'future_timestamp'
            elif age > p['max_signal_age_seconds']:
                status, strength, reason = 'stale', 0, 'stale_signal'
            relation = ('same_process' if endpoint == host and target and process == target else
                        'unrelated' if endpoint != host or (process and target and process != target) else
                        'host_context')
            if relation == 'unrelated':
                strength = 0
            ref = raw.get('event_id') or raw.get('source_id') or source_id
            if ref is not None and (not isinstance(ref, str) or not ref.strip()):
                raise ValueError('Evidence IDs must be nonempty strings')
            fingerprint = json.dumps(raw, sort_keys=True, allow_nan=False)
            ref = ref or hashlib.sha256(fingerprint.encode()).hexdigest()
            key = (source, endpoint, ref)
            if key in seen:
                if seen[key] != fingerprint:
                    raise EvidenceConflict('Evidence ID reused with different contents')
                return
            seen[key] = fingerprint
            evidence.append({'source': source, 'agent_id': endpoint, 'event_id': ref,
                             'timestamp': stamp(moment), 'process': process, 'relation': relation,
                             'group': p['groups'][source], 'contribution': round(strength, 4),
                             'status': status, 'reason': reason, 'details': deepcopy(raw)})

        model = data.get('ml')
        flat = any(k in data for k in MODEL_KEYS)
        if model is not None and flat:
            raise ValueError('Use nested ml or flat M2 response, not both')
        model = model if model is not None else (data if flat else None)
        if model is not None:
            if model.get('response_mode') is None:
                mode = 'alert_only'
            if data.get('risk_score') is not None:
                raise ValueError('Do not mix M2 probability with legacy risk_score')
            try:
                probability = number(model.get('ransomware_probability'), 0, 1)
                threshold = number(model.get('threshold'), 0, 1)
                positive = probability >= threshold
                if 'alert' in model and (type(model['alert']) is not bool or model['alert'] != positive):
                    raise ValueError('M2 alert contradicts its threshold')
                if 'prediction' in model and model['prediction'] != ('ransomware' if positive else 'benign'):
                    raise ValueError('M2 prediction contradicts its threshold')
                process = identity(model) or target
                margin = (probability - threshold) / (1 - threshold) if threshold < 1 else 0
                strength = p['weights']['ml'] * (.75 + .25 * margin) if positive else 0
                add('ml', model, strength, 'model_positive' if positive else 'model_negative', process=process)
            except (ValueError, TypeError) as exc:
                # An invalid optional ML result must not disable an independently
                # attributed decoy. It remains invalid evidence, never a negative.
                if not attributed_decoy(data.get('evidence'), data):
                    raise ValueError('Invalid M2 contract: ' + str(exc)) from exc
                errors.append({'source': 'ml', 'reason': 'invalid_model_contract'})

        def records(value):
            if value is None:
                return []
            if isinstance(value, dict):
                return [value]
            if not isinstance(value, list) or len(value) > 64 or not all(isinstance(x, dict) for x in value):
                raise ValueError('Expected an object or at most 64 evidence objects')
            return value

        for raw in records(data.get('monitoring')):
            level = raw.get('rule_level')
            if type(level) is not int or not 0 <= level <= 16 or type(raw.get('suspicious')) is not bool:
                raise ValueError('Monitoring needs rule_level 0..16 and suspicious:boolean')
            add('monitoring', raw, p['weights']['monitoring'] * level / 16 if raw['suspicious'] else 0,
                'monitoring_suspicious' if raw['suspicious'] else 'monitoring_context',
                process=identity(raw.get('process') or raw))

        decoy = data.get('evidence')
        honey = records(data.get('honeyfile'))
        if decoy is not None:
            if not isinstance(decoy, dict):
                raise ValueError('evidence must be an object')
            if decoy.get('type') in ('decoy_write', 'decoy_access', 'honeyfile_access'):
                honey.append(decoy)
        for raw in honey:
            operation = raw.get('operation') or {'decoy_write': 'WRITE', 'decoy_access': 'READ',
                                                'honeyfile_access': 'READ'}.get(raw.get('type'))
            if operation not in ('READ', 'WRITE', 'DELETE', 'RENAME', 'MOVE_OUT', 'MOVE_IN'):
                raise ValueError('Unsupported honeyfile operation')
            attributed = attributed_decoy(raw, data)
            # Only the existing authenticated attributed-decoy contract grants
            # write authority. Native M3 fields are retained as host context.
            process = identity(raw.get('process') or raw)
            add('honeyfile', raw, p['weights']['attributed_decoy'] if attributed else p['weights']['honeyfile'],
                'attributed_decoy_write' if attributed else 'unattributed_honeyfile_' + operation.lower(),
                process=process)

        for raw in records(data.get('threat_intel')):
            try:
                status = raw.get('status')
                if status in ('unavailable', 'no_match', 'stale'):
                    add('threat_intel', raw, 0, 'ti_' + status, status=status)
                    continue
                if status != 'match' or raw.get('malicious') is not True:
                    raise ValueError('A match requires malicious:true')
                checked = utc(raw['checked_at'])
                age = (now - checked).total_seconds()
                if not isinstance(raw.get('provider'), str) or not raw['provider'].strip():
                    raise ValueError('Provider required')
                kind = raw.get('indicator_type')
                if kind == 'sha256':
                    matches = self._hash(raw['indicator']) == self._hash(data.get('sha256'))
                elif kind == 'ip':
                    if not isinstance(raw.get('indicator'), str) or not isinstance(data.get('src_ip'), str):
                        raise ValueError('IP indicators must be strings')
                    matches = ipaddress.ip_address(raw['indicator']) == ipaddress.ip_address(data['src_ip'])
                else:
                    raise ValueError('Unsupported indicator type')
                valid = matches and -p['future_skew_seconds'] <= age <= p['threat_intel_max_age_seconds']
                status = 'present' if valid else ('unrelated_indicator' if not matches else 'stale')
                add('threat_intel', raw, p['weights']['threat_intel'] if valid else 0,
                    'ti_match' if valid else 'ti_' + status,
                    process=identity(raw.get('process') or raw), status=status)
            except EvidenceConflict:
                raise
            except (KeyError, ValueError, TypeError):
                errors.append({'source': 'threat_intel', 'reason': 'invalid_ti_contract'})

        current = [e for e in evidence if e['contribution'] > 0 and e['status'] == 'present']
        process_evidence = [e for e in current if e['relation'] == 'same_process'
                            and (e['source'] != 'honeyfile' or e['reason'] == 'attributed_decoy_write')]
        attributed = any(e['reason'] == 'attributed_decoy_write' for e in process_evidence)
        # Host-context sources never become process evidence by temporal proximity.
        selected = process_evidence if process_evidence else [e for e in current if e['agent_id'] == host]
        reasons = []
        if process_evidence:
            anchor = max(process_evidence, key=lambda e: e['contribution'])
            selected = [e for e in process_evidence if abs((utc(e['timestamp']) - utc(anchor['timestamp'])).total_seconds())
                        <= p['correlation_seconds']]
        groups = {e['group'] for e in selected}
        score = min(100, max((e['contribution'] for e in selected), default=0)
                    + p['weights']['corroboration'] * max(0, len(groups) - 1))
        corroborated = bool(process_evidence) and len(groups) > 1
        if not attributed and not (corroborated or (p['allow_single_signal'] and process_evidence)):
            if score >= p['bands']['high']:
                score = p['bands']['high'] - .01
                reasons.append('uncorroborated_or_unattributed_high_score_capped')
        if current:
            score = max(score, p['bands']['suspicious'])
        relevant = [e for e in evidence if e['relation'] != 'unrelated']
        tier = ('high' if score >= p['bands']['high'] else 'suspicious' if score >= p['bands']['suspicious'] else
                'normal' if any(e['status'] == 'present' for e in relevant) else 'unknown')
        correlation = ('same_process' if process_evidence and len({e['source'] for e in selected}) > 1 else 'none')
        related_process = [e for e in evidence if e['relation'] == 'same_process' and e['status'] == 'present']
        for e in current:
            if e['source'] == 'honeyfile' and e['process'] is None and any(
                    abs((utc(e['timestamp']) - utc(other['timestamp'])).total_seconds()) <= p['correlation_seconds']
                    for other in related_process):
                e['relation'] = 'possible_link'
                if correlation != 'same_process':
                    correlation = 'possible_link'
                reasons.append('honeyfile_host_time_link_is_not_process_attribution')
        if not current and any(e['relation'] == 'unrelated' for e in evidence):
            tier = 'unknown'
            reasons.append('unrelated_evidence_not_combined')
        suppressed = None
        for guard in p['benign_guards']:
            if (not attributed and now < utc(guard['expires_at']) and guard['agent_id'] == host
                    and guard['sha256'].lower() == str(data.get('sha256', '')).lower()
                    and all(data.get(k) == guard[k] for k in ('process_name', 'username') if k in guard)):
                suppressed, score, tier = guard['id'], 0, 'normal'
                reasons.append('narrow_benign_guard')
                break
        action = p['high_action'] if tier == 'high' and target else 'record_only'
        if action == 'block' and (not isinstance(data.get('src_ip'), str) or not any(
                e['source'] == 'threat_intel' and e['reason'] == 'ti_match'
                and e['relation'] == 'same_process' and e['details'].get('indicator_type') == 'ip'
                for e in selected)):
            action = 'record_only'
            reasons.append('ip_target_missing_or_not_bound_to_process')
        if action == 'disable' and not isinstance(data.get('username'), str):
            action = 'record_only'
            reasons.append('account_target_missing')
        present = {e['source'] for e in evidence if e['status'] in ('present', 'no_match') and e['relation'] != 'unrelated'}
        missing = sorted(set(SOURCES) - present)
        if attributed:
            reasons.append('independent_attributed_decoy_policy')
        if mode == 'alert_only' and not attributed:
            reasons.append('ml_alert_only_requires_review')
        if not target:
            reasons.append('process_identity_not_provided')
        result = {'schema_version': 1, 'case_id': case_id or data.get('case_id'), 'agent_id': host,
                  'source_id': source_id, 'matrix_version': p['version'], 'matrix_policy': deepcopy(p),
                  'score': round(score, 4) if tier != 'unknown' else None, 'risk_level': tier,
                  'score_scope': 'process' if process_evidence else 'host', 'process': target,
                  'correlation': correlation, 'evidence': evidence, 'invalid_sources': errors,
                  'independent_groups': sorted(groups), 'corroborated': corroborated,
                  'missing_sources': missing, 'partial_evidence': bool(missing or errors),
                  'suppressed_by': suppressed, 'reasons': reasons, 'response_mode': mode,
                  'action': action, 'next_step': 'contain' if attributed else 'review' if tier != 'normal' else 'none',
                  'target_identified': False, 'automatic_response_allowed': False,
                  'execution_allowed': False, 'execution_status': 'requires_executor_validation'}
        result['evaluated_at'] = stamp(now)
        result['decision_id'] = decision_id(result)
        return result


def decision_id(decision):
    stable = {k: v for k, v in decision.items() if k not in ('decision_id', 'evaluated_at')}
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
        hashlib.sha256(json.dumps(stable, sort_keys=True, allow_nan=False).encode()).hexdigest()))


def main():
    parser = argparse.ArgumentParser(description='Preview an M5 risk decision; never executes responses')
    parser.add_argument('--input', required=True, help='JSON evidence bundle; - reads stdin')
    parser.add_argument('--config', help='Endpoint configuration')
    parser.add_argument('--matrix', help='Matrix JSON overrides the endpoint matrix selection')
    parser.add_argument('--at', help='Explicit UTC evaluation time for recorded scenarios')
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text()) if args.config else {}
        if args.matrix:
            config.pop('risk_matrix_file', None)
            config['risk_matrix'] = json.loads(Path(args.matrix).read_text())
        body = sys.stdin.read(65537) if args.input == '-' else Path(args.input).read_text()
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError('Evidence bundle must be an object')
        result = RiskMatrix(config).evaluate(data, agent_id=config.get('agent_id') or data.get('agent_id'),
                                             now=utc(args.at) if args.at else None,
                                             occurred_at=data.get('timestamp'))
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (ValueError, TypeError, OSError) as exc:
        print('AI-RDR risk matrix: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

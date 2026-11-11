"""Separate target identification from action-specific response authority.

Inputs arrive over the trusted local/Wazuh control path. Caller-supplied decision
booleans are never authority; M5 computes these fields from its own policy.
"""

ACTIONS = frozenset(('freeze', 'kill', 'isolate', 'block', 'disable'))
DECOY_ACTIONS = ('freeze', 'kill', 'isolate')


def process_identity_valid(process):
    return bool(
        isinstance(process, dict)
        and type(process.get('pid')) is int and process['pid'] > 1
        and type(process.get('start_ticks')) is int and process['start_ticks'] >= 0
        and isinstance(process.get('boot_id'), str) and process['boot_id'].strip()
    )


def attributed_decoy(evidence, process):
    if not isinstance(evidence, dict) or not isinstance(process, dict):
        return False
    return bool(
        evidence.get('type') == 'decoy_write'
        and ('registered' not in evidence or evidence['registered'] is True)
        and isinstance(evidence.get('event_id'), str) and evidence['event_id'].strip()
        and process_identity_valid(process)
        and type(evidence.get('pid')) is int and evidence['pid'] == process['pid']
        and type(evidence.get('start_ticks')) is int and evidence['start_ticks'] == process['start_ticks']
        and evidence.get('boot_id') == process['boot_id']
    )


def validate_response_mode(mode):
    if mode not in (None, 'alert_only', 'automatic'):
        raise ValueError('Unsupported response_mode')


def response_mode(data):
    """An inner M2 alert_only cannot be overridden by an outer automatic flag."""
    model = data.get('ml')
    if model is not None and not isinstance(model, dict):
        raise ValueError('ml must be an object')
    modes = [data.get('response_mode'), (model or {}).get('response_mode')]
    for mode in modes:
        validate_response_mode(mode)
    if 'alert_only' in modes:
        return 'alert_only'
    return 'automatic' if 'automatic' in modes else None


def _actions(config, name, default=()):
    values = config.get(name, default)
    if (not isinstance(values, (list, tuple))
            or any(not isinstance(x, str) or x not in ACTIONS for x in values)):
        raise ValueError(name + ' must list supported response actions')
    return values


def response_decision(action, data, config, *, target_identified, analyst_approved=False,
                      process_verified=False):
    """Return distinct identification, permission and execution decisions.

    target_identified is computed by the executor, not read from alert JSON.
    Human approval comes only from authoritative local operation state. Neither
    identification nor an automatic input flag grants action permission alone.
    """
    if action not in ACTIONS or type(target_identified) is not bool:
        raise ValueError('Invalid response decision request')
    if type(analyst_approved) is not bool or type(process_verified) is not bool:
        raise ValueError('Invalid analyst approval')
    mode = response_mode(data)
    general = _actions(config, 'automatic_actions')
    decoy = _actions(config, 'attributed_decoy_actions', DECOY_ACTIONS)
    attributed = (attributed_decoy(data.get('evidence'), data)
                  and (target_identified if action in ('freeze', 'kill') else process_verified))
    allowed, source, reason = False, 'none', 'action_not_authorised'
    # The independent decoy path is not an ML prediction. Its policy is explicit
    # and separate, so an M2-only restriction does not disable attributed decoys.
    if attributed and action in decoy:
        allowed, source, reason = True, 'attributed_decoy', 'attributed_decoy_policy'
    elif mode == 'alert_only':
        reason = 'ml_alert_only'
    elif mode != 'automatic':
        reason = 'explicit_automatic_mode_required'
    elif action in general:
        allowed, source, reason = True, 'endpoint_policy', 'configured_automatic_action'
    # A score or generic action permission never confirms a kill target.
    if action == 'kill' and not attributed:
        allowed, source, reason = False, 'none', 'positive_evidence_required'
    # Freeze is the explicitly permitted reversible first step. Extra approval
    # gates termination and standalone network/account restrictions.
    if action != 'freeze' and (config.get('critical_asset', False) or config.get('require_approval', False)):
        allowed, source, reason = False, 'none', 'analyst_approval_required'
    execute = target_identified and (allowed or analyst_approved)
    return {'action': action, 'target_identified': target_identified,
            'automatic_response_allowed': allowed, 'execution_allowed': execute,
            'response_mode': mode, 'permission_source': 'analyst' if analyst_approved else source,
            'policy_version': config.get('policy_version', 'response-gates-v2'),
            'reason': ('target_not_identified' if not target_identified else
                       'analyst_approved' if analyst_approved else reason)}


def automatic_allowed(mode, evidence, process, *, action='freeze', config=None):
    """Compatibility helper; callers must still independently validate targets."""
    identified = process_identity_valid(process)
    decision = response_decision(action, dict(process, response_mode=mode, evidence=evidence),
                                 config or {}, target_identified=identified, process_verified=identified)
    return decision['automatic_response_allowed']

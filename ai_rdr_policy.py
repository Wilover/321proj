"""M5 automatic-response eligibility, shared by input and workflow boundaries."""


def attributed_decoy(evidence, process):
    if not isinstance(evidence, dict) or not isinstance(process, dict):
        return False
    return bool(
        evidence.get('type') == 'decoy_write'
        and isinstance(evidence.get('event_id'), str) and evidence['event_id'].strip()
        and type(process.get('pid')) is int and process['pid'] > 1
        and type(process.get('start_ticks')) is int and process['start_ticks'] >= 0
        and isinstance(process.get('boot_id'), str) and process['boot_id']
        and type(evidence.get('pid')) is int and evidence['pid'] == process['pid']
        and type(evidence.get('start_ticks')) is int and evidence['start_ticks'] == process['start_ticks']
        and evidence.get('boot_id') == process['boot_id']
    )


def validate_response_mode(mode):
    if mode not in (None, 'alert_only', 'automatic'):
        raise ValueError('Unsupported response_mode')


def automatic_allowed(mode, evidence, process):
    validate_response_mode(mode)
    # Independent attributed decoy evidence authorises its own response path.
    return mode != 'alert_only' or attributed_decoy(evidence, process)

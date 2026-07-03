def window():
    return None

def groupby():
    return None

def algorithm(event):
    evt_type = (event.get('event_type') or '').lower()
    action = (event.get('event_action') or '').lower()
    malware = (event.get('malware_name') or '').lower()
    details = str(event.get('details') or '').lower()

    tamper_keywords = [
        'tamper', 'disable', 'uninstall', 'bypass',
        'agent stopped', 'service stopped'
    ]

    if (
        any(k in evt_type for k in tamper_keywords) or
        any(k in action for k in tamper_keywords) or
        any(k in malware for k in tamper_keywords) or
        any(k in details for k in tamper_keywords)
    ):
        return 1.0

    return 0.0

def context(event):
    return (
        "Tamper protection alert triggered on host " +
        str(event.get('source_hostname')) +
        ". Detection type: " + str(event.get('event_type')) +
        ", action: " + str(event.get('event_action'))
    )

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Impair Defenses (T1562)'

def artifacts():
    return stats.collect(['source_hostname','event_type','event_action','process_name','file_path'])

def entity(event):
    return {'derived': False, 'value': event.get('source_hostname'), 'type': 'host'}
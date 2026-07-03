def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    proc = (event.get('process_name') or '').lower()
    malware = (event.get('malware_name') or '').lower()
    evt_type = (event.get('event_type') or '').lower()

    kernel_indicators = [
        '.sys', 'driver', 'rootkit', 'kernel'
    ]

    if (
        any(k in file_path for k in kernel_indicators) or
        any(k in proc for k in kernel_indicators) or
        any(k in malware for k in kernel_indicators) or
        any(k in evt_type for k in kernel_indicators)
    ):
        return 0.75

    return 0.0

def context(event):
    return (
        "Suspicious kernel-level activity detected on host " +
        str(event.get('source_hostname')) +
        ". File: " + str(event.get('file_path')) +
        ", process: " + str(event.get('process_name'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Rootkit (T1014)'

def artifacts():
    return stats.collect(['source_hostname','file_path','process_name','malware_name'])

def entity(event):
    return {'derived': False, 'value': event.get('source_hostname'), 'type': 'host'}
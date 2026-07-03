def window():
    return '5m'

def groupby():
    return ['source_ip']

def algorithm(event):
    src_ip = event.get('source_ip')

    if not src_ip:
        return 0.0

    if src_ip.startswith(('10.', '192.168.', '172.')):
        if stats.count('network_scan') >= 25:
            stats.resetcount('network_scan')
            return 0.75

    return 0.0

def context(event):
    return (
        "Internal network scanning behavior detected from source IP " +
        str(event.get('source_ip')) +
        "."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Discovery (TA0007)'

def technique():
    return 'Network Service Scanning (T1046)'

def artifacts():
    return stats.collect(['source_ip', 'event_code'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
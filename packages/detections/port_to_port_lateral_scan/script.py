def window():
    return '5m'

def groupby():
    return ['source_ip']

def algorithm(event):
    src_ip = event.get('source_ip')

    if not src_ip:
        return 0.0

    if stats.count('scan_activity') >= 20:
        stats.resetcount('scan_activity')
        return 0.75

    return 0.0

def context(event):
    return (
        "High frequency connection attempts detected from source IP " +
        str(event.get('source_ip')) +
        ", indicating possible internal port scanning."
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
def window():
    return '5m'

def groupby():
    return ['source_ip']

def algorithm(event):
    details = (event.get('event_details') or '').lower()

    if 'arp' in details and ('duplicate' in details or 'conflict' in details):
        return 0.75

    return 0.0

def context(event):
    return (
        "ARP anomaly detected from source IP " +
        str(event.get('source_ip')) +
        ", which may indicate ARP poisoning."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Adversary-in-the-Middle (T1557)'

def artifacts():
    return stats.collect(['source_ip', 'event_details'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
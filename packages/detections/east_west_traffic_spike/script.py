def window():
    return '10m'

def groupby():
    return ['source_ip']

def algorithm(event):
    src_ip = event.get('source_ip')

    if not src_ip:
        return 0.0

    # internal IP check
    if src_ip.startswith(('10.', '192.168.', '172.')):
        if stats.count('east_west') >= 15:
            stats.resetcount('east_west')
            return 0.75

    return 0.0

def context(event):
    return (
        "High volume of internal communication detected from source IP " +
        str(event.get('source_ip')) +
        " within a short duration, indicating possible east-west movement."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Remote Services (T1021)'

def artifacts():
    return stats.collect(['source_ip', 'event_facility', 'event_code'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
def window():
    return '30m'

def groupby():
    return ['source_ip']

def algorithm(event):
    src_ip = event.get('source_ip')

    if not src_ip:
        return 0.0

    if src_ip.startswith(('10.', '192.168.', '172.')):
        if stats.count('unusual_internal') >= 10:
            stats.resetcount('unusual_internal')
            return 0.50

    return 0.0

def context(event):
    return (
        "Unusual internal communication pattern detected from source IP " +
        str(event.get('source_ip')) +
        ". This may indicate lateral movement or unauthorized access."
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Remote Services (T1021)'

def artifacts():
    return stats.collect(['source_ip', 'event_details'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
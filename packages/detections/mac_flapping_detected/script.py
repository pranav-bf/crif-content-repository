def window():
    return '5m'

def groupby():
    return ['event_details']

def algorithm(event):
    details = (event.get('event_details') or '').lower()

    if 'mac flapping' in details or 'moved' in details:
        return 0.75

    return 0.0

def context(event):
    return "MAC flapping detected based on switch logs, indicating possible spoofing or loop."

def criticality():
    return 'HIGH'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Adversary-in-the-Middle (T1557)'

def artifacts():
    return stats.collect(['event_details'])

def entity(event):
    return {'derived': False, 'value': event.get('event_details'), 'type': 'rawlog'}
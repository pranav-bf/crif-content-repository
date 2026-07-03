def window():
    return '1d'

def groupby():
    return ['user']

def algorithm(event):
    risk = (event.get('risk_level') or '').lower()

    if risk == 'unsanctioned':
        if stats.count('shadow') > 5:
            return 0.50

    return 0.0

def context(event):
    return (
        "Shadow IT usage detected for user " +
        str(event.get('user')) +
        " accessing unsanctioned applications"
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Discovery (TA0007)'

def technique():
    return 'Cloud Infrastructure Discovery (T1580)'

def artifacts():
    return stats.collect(['user','application','risk_level'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
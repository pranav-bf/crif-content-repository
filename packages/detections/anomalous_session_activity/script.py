def window():
    return '15m'

def groupby():
    return ['user','session_id']

def algorithm(event):
    activity = (event.get('activity') or '').lower()

    if stats.count('activity') > 20:
        return 0.50

    return 0.0

def context(event):
    return (
        "Unusual session activity detected for user " +
        str(event.get('user'))
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['user','session_id','activity','source_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
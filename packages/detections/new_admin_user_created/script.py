def window():
    return '10m'

def groupby():
    return ['user']

def algorithm(event):
    msg = event.get('message', '').lower()
    if 'create role' in msg and 'superuser' in msg:
        return 1.0
    return 0.0

def context(event):
    return "New PostgreSQL role created with SUPERUSER privileges: " + str(event.get('message', 'No message'))

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Create Account (T1136)'

def artifacts():
    return stats.collect(['user', 'timestamp', 'message'])

def entity(event):
    return {'derived': False, 'value': event.get('user', 'unknown'), 'type': 'user'}

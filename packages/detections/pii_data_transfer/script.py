def window():
    return '10m'

def groupby():
    return ['user']

def algorithm(event):
    data_type = (event.get('data_type') or '').lower()
    action = (event.get('event_action') or '').lower()

    if data_type in ['pii','personal','ssn'] and action == 'allowed':
        return 0.75

    return 0.0

def context(event):
    return (
        "PII data transfer detected by user " + str(event.get('user')) +
        " via " + str(event.get('channel')) +
        " to destination " + str(event.get('destination'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration Over Web Services (T1567)'

def artifacts():
    return stats.collect(['user','data_type','file_name','destination','source_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
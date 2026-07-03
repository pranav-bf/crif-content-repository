def window():
    return '10m'

def groupby():
    return ['user']

def algorithm(event):
    data_type = (event.get('data_type') or '').lower()

    if data_type in ['financial','credit_card','bank']:
        return 1.0

    return 0.0

def context(event):
    return (
        "Financial data exfiltration detected by user " +
        str(event.get('user')) +
        " involving file " + str(event.get('file_name'))
    )

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration of Sensitive Data (T1020)'

def artifacts():
    return stats.collect(['user','data_type','file_name','destination'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
def window():
    return '10m'

def groupby():
    return ['user']

def algorithm(event):
    app = (event.get('application') or '').lower()
    activity = (event.get('activity') or '').lower()
    risk = (event.get('risk_level') or '').lower()

    if activity == 'upload' and risk in ['high','unsanctioned']:
        return 0.75

    return 0.0

def context(event):
    return (
        "User " + str(event.get('user')) +
        " uploaded data to unsanctioned application " +
        str(event.get('application'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration to Cloud Storage (T1567)'

def artifacts():
    return stats.collect(['user','application','activity','file_size','source_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
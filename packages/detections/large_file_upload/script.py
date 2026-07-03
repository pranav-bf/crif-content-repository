def window():
    return '5m'

def groupby():
    return ['user']

def algorithm(event):
    activity = (event.get('activity') or '').lower()
    size = int(event.get('file_size') or 0)

    if activity == 'upload' and size > 500000000:  # 500MB
        return 0.75

    return 0.0

def context(event):
    return (
        "Large file upload detected by user " +
        str(event.get('user')) +
        " to application " + str(event.get('application'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration Over Web Services (T1567)'

def artifacts():
    return stats.collect(['user','application','file_size','source_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
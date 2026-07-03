def window():
    return None

def groupby():
    return None

def algorithm(event):
    encrypted = event.get('is_encrypted')
    action = (event.get('event_action') or '').lower()

    if encrypted and action == 'allowed':
        return 0.75

    return 0.0

def context(event):
    return (
        "Encrypted data transfer detected from user " +
        str(event.get('user')) +
        " to " + str(event.get('destination'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Obfuscated/Encrypted File Transfer (T1027)'

def artifacts():
    return stats.collect(['user','destination','file_name','is_encrypted'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
def window():
    return None

def groupby():
    return None

def algorithm(event):
    oauth = (event.get('oauth_app') or '').lower()
    risk = (event.get('risk_level') or '').lower()

    if oauth and risk in ['high','unsanctioned']:
        return 0.75

    return 0.0

def context(event):
    return (
        "Suspicious OAuth token usage detected for app " +
        str(event.get('oauth_app')) +
        " by user " + str(event.get('user'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Account Access Removal (T1098)'

def artifacts():
    return stats.collect(['user','oauth_app','risk_level'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
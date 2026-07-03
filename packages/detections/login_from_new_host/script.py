def init(event):
    analysis = stats.raranomaly('host')
    session.set("rare_host", [analysis])
    return "initialized"

def window():
    return "30d"

def groupby():
    return ["user"]

def algorithm(event):
    analysis = session.get("rare_host")[0]
    rare_signal = str(analysis.get("rare_signal"))

    if rare_signal == '1.0':
        return 0.75

    return 0.0

def clusters(event):
    return session.get("rare_host")

def context(event_data):
    return (
        "User " + str(event_data.get('user')) +
        " logged in from a new or previously unseen host " +
        str(event_data.get('host')) +
        ". This deviates from normal login behavior and may indicate compromised credentials or unauthorized access."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Initial Access (TA0001)'    

def technique():    
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect([
        'user',
        'host',
        'event_type'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('user'),
        'type': 'user'
    }   
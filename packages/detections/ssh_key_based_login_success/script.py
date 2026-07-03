def init(event):
    analysis = stats.raranomaly('source_ip')
    session.set("rare_signal", [analysis])
    return "Initialized zanomaly detection"

def window():
    return "30d"

def groupby():
    return ["user"]


def algorithm(event):
    src_ip = event.get("source_ip")
    analysis = session.get("rare_signal")[0]
    rare_signal = str(analysis.get("rare_signal"))
    if rare_signal == '1.0' :
        return 0.75 

def clusters(event): 
    cluster = session.get("rare_signal")[0]
    return [cluster]


def context(event_data):
    return (
        "A successful SSH login was observed for user " + str(event_data.get('user')) +
        " from a source IP " + str(event_data.get('source_ip')) +
        " that has not been seen for this user in the past 30 days on host " + str(event_data.get('host')) +
        ". This deviation from the user’s normal login pattern may indicate credential compromise, remote attacker access, or infrastructure changes. "
        "Verify whether this login was expected, confirm the source IP ownership, and review subsequent user activity."
    )



def criticality():
    return 'HIGH'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['host', 'event_action', 'source_ip', 'process_name', 'process_id', 'source_port', 'user', 'event_action', 'process_id'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}



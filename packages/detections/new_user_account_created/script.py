def window():
    return None 

def groupby():
    return None

def algorithm(event):
    process = (event.get('process_name') or '').lower()
    details = (event.get('event_details') or '').lower()

    if process in ['useradd','adduser']:
        return 1.0

    if (
        'new user' in details or
        'account created' in details or
        'uid=' in details and 'gid=' in details
    ):
        return 1.0

    return 0.0



def context(event_data):
    return (
        "A new user account " + str(event_data.get('user')) + " with event action " + str(event_data.get('event_action')) + " was created on host " + str(event_data.get('host')) +
        " by process " + str(event_data.get('process_name')) +
        ". This may indicate persistence activity or unauthorized system access."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Persistence (TA0003)'


def technique():
    return 'Create Account (T1136)'


def artifacts():
    return stats.collect(['host','process_name','event_details', 'event_action', 'user', 'user_id'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
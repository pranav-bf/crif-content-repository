def window():
    return None

def groupby():
    return None

def algorithm(event):
    action = (event.get('event_action') or '').lower()
    process = (event.get('process_name') or '').lower()
    details = (event.get('event_details') or '').lower()

    security_agents = ['auditd','falcon','edr','osquery','sysmon']

    if action == 'stopped' and process == 'systemd' and any(agent in details for agent in security_agents):
        if 'stopped' in details or 'killed' in details or 'stop' in details:
            return 1.0

    if action == 'stopped' and process in security_agents and (
        'exiting' in details or 'terminated' in details
    ):
        return 1.0

    return 0.0



def context(event_data):
    return (
        "Security monitoring agent interruption detected on host " + str(event_data.get('host')) +
        ". Process " + str(event_data.get('process_name')) +
        " was stopped. This may indicate defense evasion."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Defense Evasion (TA0005)'


def technique():
    return 'Impair Defenses (T1562)'
def artifacts():
    return stats.collect(['host','process_name','event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
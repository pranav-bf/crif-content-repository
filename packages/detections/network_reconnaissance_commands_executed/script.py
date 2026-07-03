def window():
    return '10m'

def groupby():
    return ['host']

def algorithm(event):
    process = (event.get('process_name'))
    command = (event.get('process_command') or '').lower()

    recon_tools = ['netstat','ss','ifconfig','ip','nmap']

    if any(cmd in command for cmd in recon_tools) and process == 'sudo':
        return 0.50

    return 0.0


def context(event_data):
    return (
        "Network reconnaissance command executed on host " +
        str(event_data.get('host')) +
        " using process " + str(event_data.get('process_name')) + " and command executed is" + str(event_data.get('process_command')) +
        ". This may indicate lateral movement preparation."
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Discovery (TA0007)'


def technique():
    return 'Network Service Discovery (T1046)'


def artifacts():
    return stats.collect(['host','process_name', 'user', 'process_id', 'process_command', 'event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}
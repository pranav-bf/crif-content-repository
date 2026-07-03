def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    command = (event.get('process_command') or '').lower()
    details = (event.get('event_details') or '').lower()

    if (
        'authorized_keys' in file_path or
        'authorized_keys' in command or
        'authorized_keys' in details
    ):
        if (
            '>>' in details or
            'write' in details or
            'modify' in details or
            'create' in details or
            'echo ' in details or
            'cp ' in details or
            'mv ' in details
        ):
            return 0.75

    return 0.0



def context(event_data):
    return (
        "SSH authorized_keys file was modified on host " + str(event_data.get('host')) + " by command "+ str(event_data.get('process_command')) +
        ". This may indicate SSH persistence or unauthorized access setup."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Persistence (TA0003)'


def technique():
    return 'SSH Authorized Keys (T1098)'


def artifacts():
    return stats.collect(['host','process_name','executable','event_details', 'user_id', 'process_command'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
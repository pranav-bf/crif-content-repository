def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    details = (event.get('event_details') or '').lower()

    if '/etc/systemd/system/' in file_path and '.service' in file_path:
        if (
            'create' in details or
            'modify' in details or
            'write' in details or
            'cp ' in details or
            'mv ' in details
        ):
            return 1.0

    return 0.0



def context(event_data):
    return (
        "A new systemd service file was created or modified with process id " + str(event_data.get('process_id')) + " and file path " + str(event_data.get('file_path')) + " on host " + str(event_data.get('host')) + " by executing " + str(event_data.get('executable')) +
        ". This may indicate persistence via malicious service installation."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Persistence (TA0003)'


def technique():
    return 'Create or Modify System Process (T1543)'

def artifacts():
    return stats.collect(['host','file_path','process_name','event_details', 'executable', 'user_id', 'process_id'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    details = (event.get('event_details') or '').lower()

    if '.bash_history' in file_path:
        if (
            'delete' in details or
            'truncate' in details or
            'rm ' in details or
            'history -c' in details
        ):
            return 0.75

    return 0.0


def context(event_data):
    return (
        "Bash history file modification detected on host " + str(event_data.get('host')) +
        ". File: " + str(event_data.get('file_path')) +
        ". This may indicate attempts to hide command execution."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Defense Evasion (TA0005)'


def technique():
    return 'Indicator Removal on Host (T1070)'
def artifacts():
    return stats.collect(['host', 'user_id', 'file_path','process_name','event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
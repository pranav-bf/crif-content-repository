def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    details = (event.get('event_details') or '').lower()

    if '/var/log/' in file_path:
        if (
            'delete' in details or
            'removed' in details or
            'rm ' in details or
            'truncate' in details or
            'shred' in details
        ):
            return 1.0

    return 0.0



def context(event_data):
    return (
        "Deletion of system log files detected on host " + str(event_data.get('host')) +
        ". File path: " + str(event_data.get('file_path')) + " with executable " + str(event_data.get('executable')) + 
        ". This may indicate defense evasion activity."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Defense Evasion (TA0005)'


def technique():
    return 'Indicator Removal on Host (T1070)'
  
def artifacts():
    return stats.collect(['host','file_path','process_name', 'process_command', 'executable', 'event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
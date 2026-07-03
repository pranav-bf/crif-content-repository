def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    command = (event.get('process_command') or '').lower()
    details = (event.get('event_details') or '').lower()

    cron_paths = ['/etc/crontab','/etc/cron','/etc/cron.d','/var/spool/cron']

    if (
        any(path in file_path for path in cron_paths) or
        any(path in command for path in cron_paths) or
        any(path in details for path in cron_paths)
    ):
        if (
            'write' in details or
            'modify' in details or
            'create' in details or
            'echo ' in details or
            '>>' in details or
            'crontab -e' in details or
            'cp ' in details or
            'mv ' in details
        ):
            return 0.75

    return 0.0


def context(event_data):
    return (
        "A cron job configuration was created or modified with process id" + str(event_data.get('process_id')) + " and command " + str(event_data.get('process_command')) +" on host " + str(event_data.get('host')) +
        ". This may indicate persistence through scheduled task execution."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Persistence (TA0003)'


def technique():
    return 'Scheduled Task/Job (T1053)'


def artifacts():
    return stats.collect(['host','file_path','process_name','event_details', 'process_command', 'user_id'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
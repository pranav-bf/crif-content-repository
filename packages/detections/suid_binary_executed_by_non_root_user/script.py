def window():
    return '5m'

def groupby():
    return ['user_id']

def algorithm(event):

    details = (event.get('event_details') or '').lower()
    uid = event.get('user_id')
    process = (event.get('process_name') or '').lower()
    file_path = (event.get('file_path') or '').lower()

    if not uid or str(uid) == '0':
        return 0.0

    if 'suid=1' in details or 'setuid' in details:
        return 1.0

    known_suid_bins = [
        '/usr/bin/passwd',
        '/usr/bin/sudo',
        '/usr/bin/chsh',
        '/usr/bin/newgrp',
        '/usr/bin/gpasswd',
        '/usr/bin/mount',
        '/usr/bin/su'
    ]

    if file_path in known_suid_bins:
        return 1.0

    if 'euid=0' in details and 'uid=' in details:
        return 1.0

    return 0.0



def context(event_data):
    return (
        "SUID binary execution detected. UID " +
        str(event_data.get('user_id')) +
        " executed a privileged binary on host " +
        str(event_data.get('host')) +
        ". This may indicate privilege escalation activity."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Privilege Escalation (TA0004)'


def technique():
    return 'Setuid and Setgid (T1548)'
    
def artifacts():
    return stats.collect(['host','uid', 'event_action', 'process_name', 'file_path','event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
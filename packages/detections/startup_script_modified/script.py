def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    command = (event.get('process_command') or '').lower()
    details = (event.get('event_details') or '').lower()

    # Startup-related paths
    startup_paths = [
        '/etc/rc.local',
        '/etc/init.d/',
        '/etc/systemd/system/',
        '/lib/systemd/system/',
        '/etc/profile',
        '/etc/profile.d/',
        '.bashrc',
        '.bash_profile',
        '.profile',
        '/etc/cron',
        '/var/spool/cron'
    ]

    # Check if path or command touches startup locations
    if not any(p in file_path for p in startup_paths) and \
       not any(p in command for p in startup_paths):
        return 0.0

    # Modification indicators
    if any(x in details for x in [
        'write', 'modify', 'create', 'append', 'truncate'
    ]) or any(x in command for x in [
        'echo ', '>>', '>', 'cp ', 'mv ', 'sed ', 'tee '
    ]):
        return 0.75

    return 0.0

def context(event_data):
    return (
        "Startup script modification detected on host " + str(event_data.get('host')) +
        ". File or path: " + str(event_data.get('file_path')) +
        ". Command executed: " + str(event_data.get('process_command')) +
        ". This may indicate persistence via modification of system or user startup scripts."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Boot or Logon Autostart Execution (T1547)'

def artifacts():
    return stats.collect([
        'host',
        'file_path',
        'process_name'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }
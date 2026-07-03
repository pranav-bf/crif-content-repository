def window():
    return None


def groupby():
    return ['host']


def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    parent = (event.get('parent_process') or '').lower()
    cmd = (event.get('command_line') or '').lower()

    key = application.get("suspicious_process_spawn")

    # Prevent duplicate alerts
    if key is True:
        return 0.0

    if not proc:
        return 0.0

    suspicious = [
        'powershell', 'cmd', 'wscript', 'cscript',
        'mshta', 'rundll32', 'regsvr32'
    ]

    # Check if suspicious process is executed
    if not any(p in proc for p in suspicious):
        return 0.0

    # Basic parent validation
    if parent in ['explorer.exe', 'services.exe', 'svchost.exe']:
        return 0.0

    # Optional command-line validation (stronger signal)
    if cmd:
        if any(x in cmd for x in ['http', 'https', '-enc', 'base64']):
            application.put("suspicious_process_spawn", True, 3600)
            return 0.75

    # If no command-line but still suspicious parent-child
    if parent:
        application.put("suspicious_process_spawn", True, 3600)
        return 0.75

    return 0.0


def context(event_data):
    proc = event_data.get('process_name')
    parent = event_data.get('parent_process')
    host = event_data.get('host')
    user = event_data.get('user_name')

    context = "Suspicious process execution detected "

    if proc:
        context += "for process " + str(proc) + " "

    if parent:
        context += "spawned by " + str(parent) + " "

    if user:
        context += "under user " + str(user) + " "

    if host:
        context += "on host " + str(host) + " "

    context += "This may indicate misuse of system utilities or script-based execution."

    return context


def criticality():
    return 'HIGH'


def tactic():
    return 'Execution (TA0002)'


def technique():
    return 'Command and Scripting Interpreter (T1059)'


def artifacts():
    return stats.collect([
        'process_name',
        'parent_process',
        'command_line',
        'user_name',
        'host'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }
def window():
    return None


def groupby():
    return ['host']


def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    cmd = (event.get('command_line') or '').lower()

    key = application.get("lsass_access_attempt")

    # Prevent duplicate alerts
    if key is True:
        return 0.0

    if not proc:
        return 0.0

    suspicious_tools = [
        'procdump', 'rundll32', 'powershell',
        'wmic', 'taskmgr'
    ]

    # Must be suspicious tool
    if not any(tool in proc for tool in suspicious_tools):
        return 0.0

    # Must reference lsass
    if 'lsass' not in cmd:
        return 0.0

    # Strong indicators
    if any(x in cmd for x in [
        '-ma', 'minidump', 'comsvcs.dll',
        'sekurlsa', 'dumplsass'
    ]):
        application.put("lsass_access_attempt", True, 3600)
        return 0.75

    return 0.0


def context(event_data):
    proc = event_data.get('process_name')
    cmd = event_data.get('command_line')
    host = event_data.get('host')
    user = event_data.get('user_name')

    context = "Potential LSASS credential access attempt detected "

    if proc:
        context += "via process " + str(proc) + " "

    if user:
        context += "executed by user " + str(user) + " "

    if host:
        context += "on host " + str(host) + " "

    if cmd:
        context += "with command referencing LSASS memory access "

    context += "This behavior is commonly associated with credential dumping attacks."

    return context


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Credential Access (TA0006)'


def technique():
    return 'OS Credential Dumping (T1003)'


def artifacts():
    return stats.collect([
        'process_name',
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
def window():
    return None


def groupby():
    return ['host']


def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    cmd = (event.get('command_line') or '').lower()

    key = application.get("credential_dump_tool")

    # Prevent duplicate alerts
    if key is True:
        return 0.0

    if not proc:
        return 0.0

    # Known tools (flexible match)
    known_tools = [
        'mimikatz', 'dumpert', 'procdump'
    ]

    # Suspicious generic tools
    suspicious_bins = [
        'rundll32', 'powershell', 'wmic'
    ]

    # Check if known dumping tool
    if any(tool in proc for tool in known_tools):
        application.put("credential_dump_tool", True, 3600)
        return 0.75

    # Check suspicious binaries targeting LSASS
    if any(bin in proc for bin in suspicious_bins):
        if cmd and 'lsass' in cmd:
            if any(x in cmd for x in [
                'sekurlsa',
                'logonpasswords',
                'minidump',
                'comsvcs.dll'
            ]):
                application.put("credential_dump_tool", True, 3600)
                return 0.75

    return 0.0


def context(event_data):
    proc = event_data.get('process_name')
    cmd = event_data.get('command_line')
    host = event_data.get('host')
    user = event_data.get('user_name')

    context = "Potential credential dumping activity detected "

    if proc:
        context += "via process " + str(proc) + " "

    if user:
        context += "executed by user " + str(user) + " "

    if host:
        context += "on host " + str(host) + " "

    if cmd:
        context += "with command indicating LSASS interaction or credential extraction "

    context += "This behavior is commonly associated with credential dumping tools such as Mimikatz."

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
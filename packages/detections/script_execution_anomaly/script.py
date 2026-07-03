def window():
    return None


def groupby():
    return ['host']


def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    cmd = (event.get('command_line') or '').lower()
    url = (event.get('url') or '').lower()

    key = application.get("high_conf_psh_download")

    # Prevent duplicate alerts
    if key is True:
        return 0.0

    if not proc or not cmd:
        return 0.0

    # Strict PowerShell scope
    if 'powershell' not in proc and 'pwsh' not in proc:
        return 0.0

    # --- Strong Indicators ONLY ---

    # Encoded execution
    has_encoded = ('-enc' in cmd or 'encodedcommand' in cmd or 'frombase64string' in cmd)

    # Direct download execution
    has_download_exec = any(x in cmd for x in [
        'downloadstring',
        'invoke-webrequest',
        'iwr ',
        'new-object system.net.webclient'
    ])

    # Must have URL
    has_url = ('http://' in cmd or 'https://' in cmd or url)

    # Filter obvious internal / benign patterns
    if url:
        if any(x in url for x in [
            '127.0.0.1',
            'localhost',
            '.local',
            'intranet',
            'corp'
        ]):
            return 0.0

    # FINAL CONDITION (strict)
    if has_url and (has_encoded or has_download_exec):
        application.put("high_conf_psh_download", True, 3600)
        return 0.75

    return 0.0


def context(event_data):
    proc = event_data.get('process_name')
    cmd = event_data.get('command_line')
    url = event_data.get('url')
    host = event_data.get('host')
    user = event_data.get('user_name')

    context = "High-confidence suspicious PowerShell activity detected "

    if proc:
        context += "via process " + str(proc) + " "

    if user:
        context += "executed by user " + str(user) + " "

    if host:
        context += "on host " + str(host) + " "

    if url:
        context += "interacting with external URL " + str(url) + " "

    if cmd:
        context += "using encoded or download-based execution "

    context += "This strongly indicates potential malicious script execution or payload retrieval."

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
        'command_line',
        'url',
        'user_name',
        'host'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }
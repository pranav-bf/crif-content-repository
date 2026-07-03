def window():
    return None

def groupby():
    return None

def algorithm(event):
    cmd = (event.get('process_command') or '').lower()
    proc = (event.get('process_name') or '').lower()

    # Only curl/wget
    if 'curl' not in proc and 'wget' not in proc and 'curl' not in cmd and 'wget' not in cmd:
        return 0.0

    # Must include URL
    if 'http://' not in cmd and 'https://' not in cmd:
        return 0.0

    # Strong execution indicators
    if any(x in cmd for x in ['| bash', '| sh', '| python', '| perl']):
        return 0.75

    # Script download indicators
    if any(ext in cmd for ext in ['.sh', '.py', '.bin', '.elf']):
        return 0.75

    # Explicit download flags
    if any(x in cmd for x in ['-o', '-O', '--output', '--remote-name']):
        return 0.75

    return 0.0

def context(event_data):
    return (
        "Suspicious script download detected on host " + str(event_data.get('host')) +
        ". Process '" + str(event_data.get('process_name')) +
        "' executed command: " + str(event_data.get('process_command')) +
        ". This indicates potential remote payload retrieval and possible execution."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Execution (TA0002)'

def technique():
    return 'Command and Scripting Interpreter (T1059)'

def artifacts():
    return stats.collect(['host', 'process_name', 'process_command'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
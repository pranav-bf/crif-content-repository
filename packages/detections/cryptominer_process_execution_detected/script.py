def window():
    return None

def groupby():
    return None

def algorithm(event):
    process = (event.get('process_name') or '').lower()
    command = (event.get('process_command') or '').lower()
    details = (event.get('event_details') or '').lower()

    miner_keywords = ['xmrig','minerd','cryptominer']

    if (
        any(k in process for k in miner_keywords) or
        any(k in command for k in miner_keywords) or
        any(k in details for k in miner_keywords)
    ):
        return 1.0

    return 0.0


def context(event_data):
    return (
        "Cryptocurrency mining activity detected on host " + str(event_data.get('host')) +
        ". Process " + str(event_data.get('process_name')) + " executing " + str(event_data.get('executable')) +
        " is commonly associated with cryptomining malware."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Impact (TA0040)'


def technique():
    return 'Resource Hijacking (T1496)'

def artifacts():
    return stats.collect(['host','process_name', 'process_command', 'executable', 'event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
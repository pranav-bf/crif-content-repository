def window():
    return '30m'

def groupby():
    return ['source_ip']

def algorithm(event):
    bytes_out = event.get('network_bytes_out')

    if not bytes_out:
        return 0.0

    bytes_out = int(bytes_out)

    if bytes_out > 20000000:
        return 0.75

    # if stats.sum('bytes_out') > 50000000:
    #     return 0.75

    return 0.0


def context(event_data):
    return (
        "High outbound data transfer detected from source IP " + str(event_data.get('source_ip')) + " to destination IP" + str(event_data.get('destination_ip')) + " with bytes transferrd " + str(event_data.get('network_bytes_out')) +
        ". This may indicate potential data exfiltration activity."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Exfiltration (TA0010)'


def technique():
    return 'Exfiltration Over Command and Control Channel (T1041)'

def artifacts():
    return stats.collect(['source_ip','network_bytes_out','destination_ip', 'process_name', 'host'])


def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
def window():
    return '15m'

def groupby():
    return ['source_ip']

def algorithm(event):
    dest_ip = event.get('destination_ip')
    bytes_out = event.get('network_bytes_out')

    if not dest_ip or not bytes_out:
        return 0.0

    bytes_out = int(bytes_out)

    # ignore internal destinations
    if dest_ip.startswith('10.') or dest_ip.startswith('192.168.') or dest_ip.startswith('172.16.') or dest_ip.startswith('172.17.') or dest_ip.startswith('172.18.') or dest_ip.startswith('172.19.') or dest_ip.startswith('172.20.') or dest_ip.startswith('172.21.') or dest_ip.startswith('172.22.') or dest_ip.startswith('172.23.') or dest_ip.startswith('172.24.') or dest_ip.startswith('172.25.') or dest_ip.startswith('172.26.') or dest_ip.startswith('172.27.') or dest_ip.startswith('172.28.') or dest_ip.startswith('172.29.') or dest_ip.startswith('172.30.') or dest_ip.startswith('172.31.'):
        return 0.0

    # single spike outbound
    if bytes_out > 5000000:
        return 0.75

    return 0.0



def context(event_data):
    return (
        "Suspicious outbound network communication detected from source IP " + str(event_data.get('source_ip')) +
        " to external destination " + str(event_data.get('destination_ip')) +
        ". High outbound traffic volume may indicate command-and-control activity or data exfiltration."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Command and Control (TA0011)'


def technique():
    return 'Application Layer Protocol (T1071)'

def artifacts():
    return stats.collect(['host', 'source_ip', 'destination_ip', 'network_bytes_out', 'process_name'])


def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
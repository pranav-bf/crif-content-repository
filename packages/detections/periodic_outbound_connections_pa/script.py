def _is_internal_ip(ip):
    if not ip:
        return 0.0
    return ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.')


def init(event):
    label = 'pa_periodic_outbound'
    source = event.get('source_ip')
    interval = "1m"
    timestamp = int(event.get('eventreceivedtime') or event.get('timestamp') or 0)

    clusters = stats.beaconing(label, source, interval, timestamp)
    session.set('clusters', clusters)

    return 'Initialized periodic outbound detection'


def window():
    return '30d'


def groupby():
    return ['source_ip']


def algorithm(event):
    clusters = session.get('clusters')

    if not clusters or not isinstance(clusters, dict):
        return 0.0

    dst_ip = event.get('destination_ip')
    action = (event.get('action') or event.get('event_action') or '').lower()

    if _is_internal_ip(dst_ip):
        return 0.0

    if action and action not in ['allow', 'accept', 'permit']:
        return 0.0

    if clusters.get('detected'):
        return 0.50

    return 0.0


def clusters(event):
    return session.get('clusters')


def context(event_data):
    return (
        'Periodic outbound communication detected from source IP '
        + str(event_data.get('source_ip'))
        + ' to destination IP '
        + str(event_data.get('destination_ip'))
        + ' over port '
        + str(event_data.get('destination_port'))
        + '. The traffic follows a consistent interval pattern, which may indicate automated beaconing activity.'
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Command and Control (TA0011)'


def technique():
    return 'Application Layer Protocol (T1071)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'destination_port',
        'network_protocol',
        'action'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }

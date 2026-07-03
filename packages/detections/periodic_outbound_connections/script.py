from datetime import datetime

def init(event):

    label = "periodic_outbound"
    source = event.get("source_ip")
    interval = "HOUR_OF_DAY"
    timestamp = long(event.get("eventtime"))

    clusters = stats.beaconing(label, source, interval, timestamp)

    session.set("clusters",  [clusters])

    return "Initialized periodic outbound detection"


def window():
    return '30d'


def groupby():
    return ['source_ip']


def algorithm(event):

    clusters = session.get("clusters")

    if not clusters or not isinstance(clusters, dict) or len(anomalies_list) <= 0:
        return 0.0

    dst_ip = event.get("destination_ip")

    # Ignore internal traffic
    if dst_ip and (
        dst_ip.startswith("10.") or
        dst_ip.startswith("192.168.") or
        dst_ip.startswith("172.")
    ):
        return 0.0

    # Only periodic pattern
    cluster_entry=clusters[0]
    if cluster_entry.get("detected"):
        return 0.50

    return 0.0


def clusters(event):
    return session.get("clusters")


def context(event_data):

    return (
        "Periodic outbound communication detected from source IP "
        + str(event_data.get('source_ip')) +
        " to destination IP "
        + str(event_data.get('destination_ip')) +
        " over port "
        + str(event_data.get('destination_port')) +
        ". The traffic follows a consistent interval pattern, which may indicate automated beaconing activity."
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
        'event_action'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
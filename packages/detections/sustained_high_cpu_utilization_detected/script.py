import re

def window():
    return '10m'

def groupby():
    return ['host']

def algorithm(event):
    cpu = event.get('cpu_utilisation')

    if cpu > 90:
        if stats.count('host') >= 10:
            return 0.50

    return 0.0


def context(event_data):
    return (
        "Sustained high CPU usage detected on host " + str(event_data.get('host')) +
        ". CPU utilization exceeded 90% for an extended period, which may indicate resource abuse or malware."
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Impact (TA0040)'


def technique():
    return 'Resource Hijacking (T1496)'

def artifacts():
    return stats.collect(['host'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}
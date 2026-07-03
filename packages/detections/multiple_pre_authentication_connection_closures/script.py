def window():
    return '5m'
  
def groupby():
    return ['source_ip']
  
def algorithm(event):
    if event.get('process_name') == 'sshd' and 'Connection closed by' in event.get('event_details'):
        if stats.count('conn_closed') >= 20:
            stats.resetcount('conn_closed')
            return 0.75 
    return 0.0

def context(event_data):
    return (
        "Multiple SSH connections from {source_ip} were established and immediately closed "
        "by {proc} on host {host} without attempting authentication. "
        "More than 20 closures occurred within a 5-minute window, suggesting automated scanning."
    ).format(
        source_ip=event_data.get('source_ip'),
        host=event_data.get('host'),
        proc=event_data.get('process_name')
    )
  
def criticality():
    return 'HIGH'
  
def tactic():
    return 'Discovery (TA0007)'
  
def technique():
    return 'Network Service Scanning (T1046)'

def artifacts():
    return stats.collect(['host', 'process_name', 'event_action', 'source_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
  
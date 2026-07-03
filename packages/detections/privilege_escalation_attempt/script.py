def window():
    return None

def groupby():
    return ['host']

def algorithm(event):
    key = application.get("use_su")
  
    if key is True:
        return 0.0

    if event.get('process_name') == 'su' and 'Successful su for root' in event.get('event_details'):
      application.put("use_su", True, 86400)
      return 0.75
    return 0.0


def context(event_data):
    return "A user successfully switched to root using the 'su' command from host " + event_data.get('host') + " with source IP " + event_data.get('source_ip')

def criticality():
    return 'HIGH'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Abuse Elevation Control Mechanism (T1548)'

def artifacts():
    return stats.collect(['host', 'process_name', 'event_action'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'username'}
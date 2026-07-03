def window():
    return None

def groupby():
    return None


def algorithm(event):
    host = event.get('host')
    user_ip = event.get('source_ip')
    # key = application.get("shell_spawned")
  
    # if key is True:
    #     return 0.0
      
    if event.get('event_action') == 'bash' and '/dev/tcp/' in event.get('event_details'):
        # application.put("shell_spawned", True, 86400)
        return 1.0  # High confidence for reverse shell
    if event.get('event_action') == 'nc' and ' -e ' in event.get('event_details'):
        # application.put("shell_spawned", True, 86400)
        return 1.0
    return 0.0

def context(event_data):
    return "Potential reverse shell spawned on host " + str(event_data.get('host')) + " with source IP " + str(event_data.get('source_ip'))

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Command and Control (TA0011)'

def technique():
    return 'Application Layer Protocol (T1071)'
  
def artifacts():
    return stats.collect(['host', 'event_action', 'source_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
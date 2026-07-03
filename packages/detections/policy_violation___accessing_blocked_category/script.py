def window():
    return None

def groupby():
    return None

def automate():
    return False

def algorithm(event):  
    action = event.get('event_action')
    subtype = event.get('log_subtype')
    appcat = event.get('application_category')

    # Trigger if type matches and destination IP is malicious
    if action == 'blocked' and subtype == 'webfilter' and appcat in ['Adult.Content', 'Proxy.Avoidance']:
        return 0.50
    return 0.0

def context(event_data):
    return str(event_data.get('event_details')) + " from source ip " + str(event_data.get('source_ip')) + " and source port " + str(event_data.get('source_port')) + " to destination ip " + str(event_data.get('destination_ip')) + " and destination port " + str(event_data.get('destination_port'))

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Command and Control (TA0011)'

def technique():
    return 'Application Layer Protocol (T1071)'

def artifacts():
    return stats.collect(['event_severity', 'event_action', 'event_alert'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'device'}
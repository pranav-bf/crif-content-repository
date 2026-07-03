
def window():
    return '30m'
def groupby():
    return ['user_name']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):

    if event.get('event_id') == 20225 and event.get('location') not in ['US', 'UK', 'CA']:
        return 0.75 
    return 0.0
def context(event_data):
    return "VPN connection from an unusual location: " + event_data.get('location')
def criticality():
    return 'HIGH'
  
def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['user_name', 'location', 'event_id'])
def entity(event):
    return {'derived': False, 'value': event.get('user_name'), 'type': 'user'}
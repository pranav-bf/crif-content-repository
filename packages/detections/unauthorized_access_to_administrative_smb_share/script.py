def window():
    return None
def groupby():
    return None
# def investigate():
#     return "windows_server_session_analyser"

# def automate():
#     return False
def algorithm(event):
    if event.get('event_id') == "5145" and event.get('share_name') in ['C$', 'ADMIN$']:
        return 0.75
    return None
def context(event_data):
    return "Unauthorized access attempt to SMB share " + event_data.get('share_name')
def criticality():
    return 'HIGH'
def tactic():
    return 'Lateral Movement (TA0008)'
def technique():
    return 'Remote Services (T1021/002)'
def artifacts():
    return stats.collect(['share_name','event_category','event_type','host','source_account_name','source_account_domain','source_port'])
def entity(event):
    return {'derived': False, 'value': event.get('share_name'), 'type': 'service'}
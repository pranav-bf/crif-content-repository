# sample name -> realtime-detections/authentication/brute_force_login.py
def window():
    return '5m'
def groupby():
    return 'account_name'
def algorithm(event):
    if event['event_id'] == 4625 and event['logon_type'] in [2, 3, 10]:
        if stats.count('account_name') >= 5:
            return 0.8
    return 0.0
def context(event_data):
    return "Multiple failed login attempts detected for account " + event_data['account_name'] + " from IP " + event_data['source_ip'] + "."
def criticality():
    return 'HIGH'
def tactic():
    return 'Credential Access (TA0006)'
def technique():
    return 'Brute Force (T1110)'
def artifacts():
    return stats.collect(['account_name', 'source_ip', 'event_id', 'logon_type'])
def entity(event):
    return {'derived': False, 'value': event['account_name'], 'type': 'user'}
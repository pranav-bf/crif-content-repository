"""
Instructions for Content Creators:
- Implement the required functions based on your detection algorithm and use case.
- Each function has a placeholder for customization.
"""

#Add your code here
def window():
    return None

def groupby():
    return None

def algorithm(event):
    if event.get('event_type') in ['AUDIT_SUCCESS', 'AUDIT_FAILURE'] and event.get('action_id') in ['EX', 'APRL', 'DPRL']:
        return 0.75
    return 0.0


def context(event):
    return 'Database Role Changes were made using the statement ' + str(event.get('statement', '')) + ' by user ' + str(event.get('user_name', '')) + ' on database ' + str(event.get('database_name', ''))

def criticality():
    return 'HIGH'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Valid Accounts (T1071)'

def artifacts():
    return stats.collect(['tenant', 'event_type', 'source_account_name', 'source_account_type', 'event_code'])

def entity(event):
    return {'derived': False, 'value': event['source_account_name'], 'type': 'accountname'}
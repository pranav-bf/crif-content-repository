def window():
    return '5m'

def groupby():
    return ['source_account_name']

def algorithm(event):
    if str(event.get('event_id')) == '4624':
        if event.get('logon_type') == '3':
            if stats.count('pth') >= 5:
                stats.resetcount('pth')
                return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Network logon detected for user " +
        str(event.get('source_account_name')) +
        " which may indicate Pass-the-Hash activity."
    )

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Pass the Hash (T1550.002)'

def artifacts():
    return stats.collect([
        'source_account_name',
        'source_ip',
        'logon_type'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('source_account_name'),
        'type': 'accountname'
    }
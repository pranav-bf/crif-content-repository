def window():
    return '10m'

def groupby():
    return ['source_account_name']

def algorithm(event):
    if str(event.get('event_id')) == '4769':
        if stats.count('ptt') >= 5:
            stats.resetcount('ptt')
            return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Kerberos ticket usage anomaly detected for user " +
        str(event.get('source_account_name')) +
        ". Possible Pass-the-Ticket activity."
    )

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Pass the Ticket (T1550.003)'

def artifacts():
    return stats.collect([
        'source_account_name',
        'source_ip',
        'event_id'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('source_account_name'),
        'type': 'accountname'
    }
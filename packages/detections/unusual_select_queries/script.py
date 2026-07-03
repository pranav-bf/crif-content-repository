def window():
    return "5m"

def groupby():
    return ["database_principal_name", "ip_address"]

def algorithm(event):
    query = (event.get('statement') or '').lower()

    if not query or 'select' not in query:
        return 0.0

    suspicious = False

    # Full table dump
    if 'select *' in query:
        suspicious = True

    # No filtering or limits
    if 'where' not in query and 'top' not in query and 'limit' not in query:
        suspicious = True


    sensitive_keywords = [
        'user', 'account', 'login',
        'credential', 'password',
        'payment', 'card', 'ssn'
    ]

    if any(k in query for k in sensitive_keywords):
        suspicious = True

    if not suspicious:
        return 0.0


    if stats.count('suspicious_select') >= 10:
        stats.resetcount('suspicious_select')
        return 0.50

    return 0.0

def context(event):
    return (
        "Unusual SELECT query activity detected. User " +
        str(event.get('database_principal_name')) +
        " from IP " + str(event.get('ip_address')) +
        " executed multiple queries that may indicate large-scale data access or scraping."
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Collection (TA0009)'

def technique():
    return 'Data from Information Repositories (T1213)'

def artifacts():
    return stats.collect([
        'database_principal_name',
        'ip_address',
        'statement',
        'database_name'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('database_principal_name'),
        'type': 'accountname'
    }
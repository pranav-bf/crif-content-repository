def window():
    return "5m"

def groupby():
    return ["database_principal_name", "ip_address"]

def algorithm(event):
    query = (event.get('statement') or '').lower()

    if not query:
        return 0.0

    # Schema discovery patterns
    schema_patterns = [
        'information_schema',
        'sys.tables',
        'sys.columns',
        'sys.objects',
        'sys.databases',
        'pg_catalog',
        'show tables',
        'show databases'
    ]

    if any(p in query for p in schema_patterns):
        if stats.count('schema_enum') >= 5:
            stats.resetcount('schema_enum')
            return 0.50

    return 0.0

def context(event):
    return (
        "Repeated schema enumeration activity detected for user " +
        str(event.get('database_principal_name')) +
        " from IP " + str(event.get('ip_address')) +
        " on database " + str(event.get('database_name')) +
        ". Queries accessing system metadata were executed multiple times, "
        "which may indicate reconnaissance activity."
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Discovery (TA0007)'

def technique():
    return 'Account Discovery (T1087)'

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
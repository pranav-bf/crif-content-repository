def window():
    return "5m"

def groupby():
    return ["database_principal_name", "ip_address"]

def algorithm(event):
    query = (event.get('statement') or '').lower()

    if not query:
        return 0.0

    # Metadata access patterns
    metadata_patterns = [
        'information_schema',
        'sys.tables',
        'sys.columns',
        'sys.objects',
        'sys.databases',
        'pg_catalog'
    ]

    # Only count metadata queries
    if any(p in query for p in metadata_patterns):
        if stats.count('metadata_spike') >= 20:
            stats.resetcount('metadata_spike')
            return 0.50

    return 0.0

def context(event):
    return (
        "Spike in metadata access detected for user " +
        str(event.get('database_principal_name')) +
        " from IP " + str(event.get('ip_address')) +
        " on database " + str(event.get('database_name')) +
        ". A high number of metadata queries were executed in a short time, "
        "which may indicate automated reconnaissance or database exploration."
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
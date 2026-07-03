# Detection: New Server Added to Domain
# Purpose: Detect when a new computer account (server) is added to the domain — potential unauthorized system join.
# Events: 4741 (A computer account was created)
# Condition: Event 4741 on Domain Controller by non-admin or unexpected actor
# MITRE: Create Account (T1136) / Persistence (TA0003)

def window():
    return '5m'


def groupby():
    # Group by creator account and host (Domain Controller)
    return ['host', 'source_account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False

  
def algorithm(event):
    evt_id = event.get('event_id')
    if evt_id != "4741":
        return 0.0

    actor = event.get('source_account_name').upper()
    host = event.get('host').upper()
    created_account = event.get('destination_account_name').upper()

    if not actor or not host or not created_account:
        return 0.0

    # Optional: restrict to domain controllers (host name check)
    if "DC" not in host and "DOMAIN" not in host:
        return 0.0

    # Allowlist known admin/service accounts that can join computers to domain
    ALLOWED_CREATORS = ['ADMIN', 'DOMAIN\\ADMINISTRATOR', 'SYSTEM', 'NETSETUP', 'COMPUTER$']
    for allowed in ALLOWED_CREATORS:
        if allowed in actor:
            return 0.0

    # If none of the allowlisted accounts created the new computer object, flag as suspicious
    return 0.75

def context(event_data):
    actor = event.get('source_account_name')
    host = event.get('host').upper()
    created_account = event.get('destination_account_name')

    return "New computer account '%s' was added to the domain on host %s by user %s." % (created, host, actor)

def criticality():
    return "HIGH"

def tactic():
    return "Persistence (TA0003)"

def technique():
    return "Create Account (T1136)"

def artifacts():
    return stats.collect([
     
      
        "host",

        "source_account_name",

        "destination_account_name"
    ])

def entity(event):
    created = event.get('destination_account_name')
    return {"derived": False, "value": created, "type": "accountname"}

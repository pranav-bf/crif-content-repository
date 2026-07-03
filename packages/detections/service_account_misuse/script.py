# Detection: Service Account Misuse
# Purpose: Detect non-service activity by service accounts (4624 with LogonType != 5)
# Events: 4624 (Successful logon)
# Condition: logon by an account that looks like a service account while logon type is not 5
# MITRE: Valid Accounts (T1078) / Credential Access (TA0006)


def window():
    return None

def groupby():
    return None

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def _is_service_account(name):
    if not name:
        return False
    n = name.strip().lower()

    # Machine accounts (end with $)
    if n.endswith("$"):
        return True

    # Common naming conventions for service accounts
    patterns = [
        "svc_", "svc-", "svc.", "service", "gmsa", "msa",
        "managedsvc", "sa_", "sa-", "appsvc"
    ]
    for p in patterns:
        if p in n:
            return True

    # Built-in Windows service accounts
    built_in = ["system", "localservice", "networkservice"]
    if n in built_in:
        return True

    return False

def algorithm(event):
    # event id check (handle string or int-ish)
    evt = event.get('event_id')

    if evt != 4624:
        return 0.0

    account = event.get("destination_account_name")

    # determine logon type safely
    logon_type = int(event.get('logon_type'))
    source_ip = event.get("source_ip")
    if source_ip in [None, "-", "UNKNOWN", "::1", "127.0.0.1"]:
        return 0.0

    # If account looks like a service account and logon type is not 5 (service), flag it
    if _is_service_account(account) and logon_type != 5:
        return 0.75

    return 0.0


  


def context(event):
    acct = event.get('destination_account_name')
    host = event.get("host") 
    lt = event.get('logon_type')
    ip = event.get("source_ip")
    return (
        "Service or machine account '%s' performed a non-service logon "
        "(LogonType=%s) on host '%s' from IP '%s'. "
        "This behavior is abnormal for service accounts "
        "and may indicate credential misuse or lateral movement."
    ) % ( acct, str(lt), host, ip)




def criticality():
    return "HIGH"

def tactic():
    return "Credential Access (TA0006)"

def technique():
    return "Valid Accounts (T1078)"

def artifacts():
    return stats.collect([
      "event_id",
        "destination_account_name",
        "destination_account_domain",
        "host",
        "logon_type",
        "source_ip",
      "source_port",

    ])



def entity(event):
    acct = event.get('destination_account_name')
    return {"derived": False, "value": acct, "type": "accountname"}

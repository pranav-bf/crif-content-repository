
WHITELIST_ACCOUNT_PREFIXES = ["svc_", "backup_", "monitoring_", "system_"]
def window():
    return '10m'
def groupby():
    return ['destination_account_name', 'host']

# def investigate():
#     return "windows_server_session_analyser"

# def automate():
#     return False

def _is_whitelisted_account(account):
    if not account:
        return False
    n = account.lower()
    return any(n.startswith(p) for p in WHITELIST_ACCOUNT_PREFIXES)

def _is_whitelisted_ip(ip):
    allowed_ip = tpi.query("AllowedIP", "ip = ?", [ip])

    # If no records found, it's unmanaged
    if not allowed_ip or not allowed_ip.get('rows'):
        return True

    # Extract allowed/known IPs
    allowed_ips = [row[0] for row in allowed_ip.get('rows', [])]
    print(allowed_ips)

    # If IP is not in known list, mark as unmanaged
    return ip not in allowed_ips
  
def algorithm(event):
    if event.get("event_id") != 4624:
        return 0.0

    if event.get('logon_type') not in ['2', '3', '10']:
        return 0.0
      
    source_ip = event.get('source_ip')
    account = event.get("destination_account_name")
    if not source_ip or source_ip in ['::1', 'UNKNOWN', '127.0.0.1', '-']:
      return 0.0

    # Skip whitelisted IPs and service accounts
    if _is_whitelisted_ip(source_ip) or _is_whitelisted_account(account):
        return 0.0
      
    sourceipsdict = stats.accumulate(['source_ip'])
    unique_ips=len(sourceipsdict.get("source_ip"))
    if unique_ips>4:
       stats.dissipate(['source_ip'])
      
    if unique_ips == 4:
      return 0.5
    return 0.0


def context(event_data):
    account = event_data.get('destination_account_name') or "-"
    host = event_data.get('host') or "-"
    recent_ip = event_data.get('source_ip') or "-"
    return (
        "User '%s' logged in from 4 differnt ips within 10 minutes "
        "on host '%s'. Most recent IP: %s. This may indicate credential reuse or unauthorized access."
    ) % (account, host, recent_ip)


  
def criticality():
    return 'MEDIUM'
def tactic():
    return 'Persistence (TA0003)'
def technique():
    return 'Valid Accounts (T1078)'
def artifacts():
    return stats.collect(['host', 'destination_account_name', 'source_ip', 'logon_type'])
def entity(event):
    return {'derived': False, 'value': event.get('destination_account_name'), 'type': 'accountname'}
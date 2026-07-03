def window():
    return '5m'

def groupby():
    # track per host and user (printer client)
    return ['host', 'source_account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    # normalize event id (safe default 0)
    evt_id = event.get('event_id')

    # only consider PrintService event 307
    if evt_id != "307":
        return 0.0

    user = event.get('source_account_name')
    host = event.get('host')

    # per-user+host counter key
    key = "printflooddetection"

    # if more than 50 print jobs in window => medium alert
    if stats.count(key) > 50:
        return 0.5

    return 0.0

def context(event_data):
    user = event_data.get('source_account_name')
    host = event_data.get('host')
    return "High volume of print jobs detected: more than 50 print requests from user %s on host %s within %s." % (user, host, window())

def criticality():
    return "MEDIUM"

def tactic():
    return "Impact (TA0040)"

def technique():
    return "Service Exhaustion Flood (T1499)"

def artifacts():
    return stats.collect([
       
        "host",
        "source_account_name",
        "job_name",
        "printer_name",
        "document_name"
    ])

def entity(event):
    actor = event.get('source_account_name')
    return {"derived": False, "value": actor, "type": "accountname"}

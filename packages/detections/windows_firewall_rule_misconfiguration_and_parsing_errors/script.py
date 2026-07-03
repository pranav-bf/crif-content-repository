# Detection: Windows Firewall Rule Misconfiguration and Parsing Errors
# Purpose: Detect Windows Firewall audit failures caused by rule parsing or port resolution issues,
#          indicating potential security gaps or misconfiguration.
# Schema: Unified `source_` / `destination_` naming
# MITRE: Defense Evasion (TA0005) / Impair Defenses: Disable or Modify System Firewall (T1562.004)

def window():
    # Short window; events are independent
    return '10m'

def groupby():
    # Group by host — multiple related parsing errors per system
    return ['host']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):


    evt_id = str(event.get("event_id") or "")
    src = (event.get("event_source") or "").lower()
    msg = (event.get("event_message") or event.get("message") or "").lower()

    #  Only consider firewall-related logs
    fw_sources = [
        "microsoft-windows-windows firewall",
        "microsoft-windows-windows firewall with advanced security",
        "microsoft-windows-windows filtering platform",
        "windows filtering platform"
    ]

    if not any(fs in src for fs in fw_sources):
        return 0.0

    #  Event IDs commonly associated with Windows Firewall issues (adjust if needed)
    valid_event_ids = ["5021", "5022", "5023", "5030", "5031", "5032", "5033", "5034", "5035"]

    #  Trigger keywords for rule parsing / audit failures
    trigger_keywords = [
        "failed to parse", "parse error", "invalid rule", "port resolution",
        "could not resolve port", "failed to resolve port", "audit failure",
        "rule parsing", "policy parsing failed", "malformed rule"
    ]

    #  Detection logic
    if evt_id in valid_event_ids or any(k in msg for k in trigger_keywords):
        return 0.9  # fixed score for confirmed misconfiguration

    return 0.0

def context(event_data):
    host = event_data.get("host") or "-"
    evt_id = event_data.get("event_id") or "-"
    src = event_data.get("event_source") or "-"
    msg = (event_data.get("event_message") or event_data.get("message") or "-")[:500]

    return (
        "Windows Firewall parsing or audit failure detected on host '%s' "
        "(Event ID: %s, Source: %s). Message excerpt: '%s'. "
        "This indicates a potential firewall misconfiguration or rule parsing issue."
    ) % (host, evt_id, src, msg)

def criticality():
    # fixed criticality — corresponds to the fixed score (0.9)
    return "MEDIUM"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Impair Defenses (T1562/004)"

def artifacts():
    return stats.collect([
        "event_id",
        "host",
        "event_source",
        "event_message"
    ])

def entity(event):
    host = event.get("host")
    return {"derived": False, "value": host, "type": "hostname"}

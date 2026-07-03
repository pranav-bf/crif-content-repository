def window():
    return "1h"  


def groupby():
    return ["source_ip"]

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    if event.get("event_id") == 5501:
        query = event.get("query_name", "").lower()
        suspicious_patterns = ["-", "_", "base64", "cmd", "dns", ".xyz", ".top", ".tk"]

        if any(p in query for p in suspicious_patterns):
            stats.count("suspicious_dns_queries")
            return 0.0

    # Evaluate threshold
    prior_suspicious = stats.getcount("suspicious_dns_queries")
    if prior_suspicious > 20:
        return 0.5

    return 0.0


def context(event_data):
    return (
        "Multiple suspicious or malformed DNS queries were observed from source IP "
        + event_data.get("source_ip", "unknown")
        + ", including domain name "
        + event_data.get("query_name")
        + ". This pattern may indicate DNS tunneling or command-and-control communication attempts."
    )


def criticality():
    return "MEDIUM"


def tactic():
    return "Command and Control (TA0011)"


def technique():
    return "Application Layer Protocol (T1071)"


def artifacts():
    return stats.collect(["query_name", "source_ip"])


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}

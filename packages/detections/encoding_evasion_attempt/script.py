def window():
    return None

def groupby():
    return None

def algorithm(event):
    url = (event.get("url") or "").lower()

    if "%2e%2e" in url or "%252e" in url:
        return 0.75
    return 0.0

def context(event):
    return "Encoding evasion attempt detected in URL " + str(event.get("url"))

def criticality():
    return "HIGH"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Obfuscated Files or Information (T1027)"

def artifacts():
    return stats.collect(["url","source_ip"])

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
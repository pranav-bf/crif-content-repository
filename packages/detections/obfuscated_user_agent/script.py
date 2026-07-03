def window():
    return None

def groupby():
    return None

def algorithm(event):
    ua = (event.get("user_agent") or "").lower()

    if len(ua) > 200 or "base64" in ua or "%20" in ua:
        return 0.50
    return 0.0

def context(event):
    return "Obfuscated user-agent detected from " + str(event.get("source_ip"))

def criticality():
    return "MEDIUM"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Obfuscated Files or Information (T1027)"

def artifacts():
    return stats.collect(["source_ip","user_agent"])

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
def window():
    return None

def groupby():
    return None

def algorithm(event):
    url = (event.get("url") or "").lower()

    if any(ext in url for ext in [".php",".jsp",".asp",".aspx"]):
        return 0.50
    return 0.0

def context(event):
    return "Suspicious script execution via URL " + str(event.get("url"))

def criticality():
    return "MEDIUM"

def tactic():
    return "Persistence (TA0003)"

def technique():
    return "Server Software Component (T1505)"

def artifacts():
    return stats.collect(["url","source_ip"])

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
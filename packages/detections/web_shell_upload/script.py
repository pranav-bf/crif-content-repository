def window():
    return "10m"

def groupby():
    return ["source_ip"]

def algorithm(event):
    method = (event.get("method") or "").upper()
    url = (event.get("url") or "").lower()

    if method in ["POST","PUT"] and any(ext in url for ext in [".php",".jsp",".aspx",".asp"]):
        return 0.75
    return 0.0

def context(event):
    return "Potential web shell upload from " + str(event.get("source_ip"))

def criticality():
    return "HIGH"

def tactic():
    return "Persistence (TA0003)"

def technique():
    return "Server Software Component (T1505)"

def artifacts():
    return stats.collect(["source_ip","url","method"])

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
def window():
    return "5m"

def groupby():
    return ["source_ip"]

def algorithm(event):
    url = (event.get("url") or "").lower()
    patterns = ["cmd=", "exec=", "powershell", "/bin/sh", "bash -c", "wget ", "curl "]

    if any(p in url for p in patterns):
        return 0.75
    return 0.0

def context(event):
    return "Possible RCE attempt from " + str(event.get("source_ip")) + " using URL " + str(event.get("url"))

def criticality():
    return "HIGH"

def tactic():
    return "Initial Access (TA0001)"

def technique():
    return "Exploit Public-Facing Application (T1190)"

def artifacts():
    return stats.collect(["source_ip","url","method"])

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
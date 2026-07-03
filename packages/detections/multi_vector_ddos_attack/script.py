def window():
    return "2m"

def groupby():
    return ["destination_ip"]

def algorithm(event):
    return 1.0

def context(event):
    return "This detection triggered because multiple attack vectors were observed against the same target within a 2 minute window. Target=%s. Multi-vector attacks are more complex and harder to mitigate than single-vector floods." % (
        event.get("destination_ip", "unknown")
    )

def criticality():
    return "CRITICAL"

def tactic():
    return "Impact (TA0040)"

def technique():
    return "Network Denial of Service (T1498)"

def entity(event):
    return {"derived": False, "value": event.get("destination_ip"), "type": "ipaddress"}
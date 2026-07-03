def window():
    return None

def groupby():
    return None

def algorithm(event):
    status = (event.get("device_status") or "").lower()
    action = (event.get("event_action") or "").lower()

    if status == "unauthorized" and action == "success":
        return 1.0

    return 0.0

def context(event):
    return (
        "Unauthorized device connected to network. MAC: " +
        str(event.get("mac_address")) +
        ", IP: " + str(event.get("ip_address"))
    )

def criticality():
    return "CRITICAL"

def tactic():
    return "Initial Access (TA0001)"

def technique():
    return "Valid Accounts (T1078)"

def artifacts():
    return stats.collect(["mac_address","ip_address","device_name","user"])

def entity(event):
    return {"derived": False, "value": event.get("mac_address"), "type": "mac"}
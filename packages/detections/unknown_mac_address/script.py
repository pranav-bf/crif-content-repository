def window():
    return "10m"

def groupby():
    return ["mac_address"]

def algorithm(event):
    mac = event.get("mac_address")
    status = (event.get("device_status") or "").lower()

    if status == "unknown":
        if stats.count("unknown_mac") > 3:
            return 0.75

    return 0.0

def context(event):
    return (
        "Unknown MAC address detected: " +
        str(event.get("mac_address")) +
        " attempting network access"
    )

def criticality():
    return "HIGH"

def tactic():
    return "Initial Access (TA0001)"

def technique():
    return "Valid Accounts (T1078)"

def artifacts():
    return stats.collect(["mac_address","ip_address","device_name"])

def entity(event):
    return {"derived": False, "value": event.get("mac_address"), "type": "mac"}
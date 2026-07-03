def window():
    return "5m"

def groupby():
    return ["host","user"]

def algorithm(event):
    file_path = (event.get("file_path") or "").lower()
    process = (event.get("process_name") or "").lower()
    details = (event.get("event_details") or "").lower()

    log_paths = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/"
    ]

    deletion_actions = [
        "delete", "unlink", "truncate", "rm ", "rm -f", "history -c"
    ]

    # direct file path targeting logs
    if any(p in file_path for p in log_paths):
        if any(a in details for a in deletion_actions):
            return 0.75

    # command-based detection
    if process in ["rm","truncate","sh","bash"]:
        if "/var/log" in details:
            return 0.75

    return 0.0

def context(event):
    return (
        "Log file deletion or tampering detected on host " +
        str(event.get("host")) +
        " by user " + str(event.get("user")) +
        ". File: " + str(event.get("file_path"))
    )

def criticality():
    return "HIGH"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Indicator Removal on Host (T1070)"

def artifacts():
    return stats.collect([
        "host",
        "user",
        "process_name",
        "file_path",
        "event_details"
    ])

def entity(event):
    return {"derived": False, "value": event.get("host"), "type": "host"}
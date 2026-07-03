def window():
    return None

def groupby():
    return []

def init(event):
  session.set("event", event)
  return "initialise"

def algorithm(event):
    resolution = event.get("resolution")
  
    if resolution == 'false_postive' or resolution == 'ignored':
        return 0.0

    parent = event.get("parent_details", {})
    parent_proc = parent.get("filename", "").lower()
    parent_cmd = parent.get("cmdline", "").lower()

    proc_name = event.get("filename", "").lower()
    cmdline = event.get("cmdline", "").lower()

    suspicious_interpreters = [
        "powershell",
        "wscript",
        "cscript",
        "mshta",
        "node.exe",
        "python.exe",
        "rundll32"
    ]

    suspicious_paths = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\users\\public\\"
    ]

    is_scheduled = parent_proc == "svchost.exe" and "schedule" in parent_cmd
    uses_cmd = proc_name == "cmd.exe"
    uses_interpreter = any(i in cmdline for i in suspicious_interpreters)
    uses_writable_path = any(p in cmdline for p in suspicious_paths)

    if is_scheduled and uses_cmd and uses_interpreter and uses_writable_path:
        return 0.75

    return 0.0


def context(event):
    parent = event.get("parent_details", {})
    parent_proc = parent.get("filename", "").lower()
    parent_cmd = parent.get("cmdline", "").lower()

    proc_name = event.get("filename", "").lower()
    cmdline = event.get("cmdline", "").lower()

    device = event.get("device", {})
    host = device.get("hostname") or (
        event.get("host_names")[0] if event.get("host_names") else "unknown host"
    )
    device_id = device.get("device_id")
    user = event.get("user_principal") or event.get("user_name")
    src_ip = device.get("external_ip") or device.get("local_ip")
    desc = event.get("description", "")

    is_scheduled = parent_proc == "svchost.exe" and "schedule" in parent_cmd
    uses_cmd = proc_name == "cmd.exe"

    suspicious_interpreters = [
        "powershell",
        "wscript",
        "cscript",
        "mshta",
        "node.exe",
        "python.exe",
        "rundll32"
    ]

    suspicious_paths = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\users\\public\\"
    ]

    interpreter_used = None
    for i in suspicious_interpreters:
        if i in cmdline:
            interpreter_used = i
            break

    writable_path_used = None
    for p in suspicious_paths:
        if p in cmdline:
            writable_path_used = p
            break

    matched = False
    if is_scheduled or interpreter_used or writable_path_used:
        matched = True

    if not matched:
        return desc

    summary = "Suspicious execution activity was observed"

    if is_scheduled:
        summary += " via the Task Scheduler"

    summary += " on host " + host

    if device_id:
        summary += " (device ID " + device_id + ")"

    if user:
        summary += " under user " + user

    if src_ip:
        summary += " from source IP " + src_ip

    summary += ". "

    if is_scheduled and uses_cmd:
        summary += (
            "The Task Scheduler service launched cmd.exe, "
            "which was used as an execution launcher. "
        )

    if interpreter_used:
        summary += (
            "A scripting or interpreter-based binary ("
            + interpreter_used +
            ") was observed in the command line. "
        )

    if writable_path_used:
        summary += (
            "The execution referenced a user-writable directory ("
            + writable_path_used +
            "), which is commonly abused for persistence or post-exploitation. "
        )

    if cmdline:
        summary += "Observed command line: " + cmdline + "."

    return summary

def criticality():
    return "HIGH"

def tactic():
    return "Persistence (TA0003)"

def technique():
    return "Scheduled Task/Job (T1053)"

def artifacts():
    event = session.get("event")
    device = event.get("device", {})
    network = event.get("network_accesses", [])

    remote_ip = None
    if network:
        remote_ip = network[0].get("remote_address")

    return {
        "host": device.get("hostname"),

        "source_ip": device.get("local_ip") or device.get("external_ip"),
        "destination_ip": remote_ip,

        "file_name": event.get("filename"),
        "file_path": event.get("filepath"),
        "command_line": event.get("cmdline"),

        "file_hash": event.get("sha256") or event.get("md5")
    }

def entity(event):
    device = event.get("device", {})

    hostname = device.get("hostname")
    return {
        "derived": False,
        "value": hostname,
        "type": "host"
    }

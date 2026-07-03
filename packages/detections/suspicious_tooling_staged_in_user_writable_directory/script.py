
def window():
    return None

def groupby():
    return []

def init(event):
  session.set("event", event)
  return "initialize"

def algorithm(event):
    resolution = event.get("resolution")
  
    if resolution == 'false_postive' or resolution == 'ignored':
        return 0.0

    # Handle wrapped events
    if "events" in event and event["events"]:
        event = event["events"][0]

    files_written = event.get("files_written", [])
    if not files_written:
        return score

    suspicious_interpreters = [
        "python",
        "pythonw",
        "node",
        "deno",
        "esbuild",
        "powershell"
    ]

    suspicious_paths = [
        "\\appdata\\local\\",
        "\\appdata\\roaming\\",
        "\\users\\public\\",
        "\\.tmp",
        "\\."
    ]

    interpreter_found = False
    writable_path_found = False

    for f in files_written:
        fname = f.get("filename", "").lower()
        fpath = f.get("filepath", "").lower()

        for interp in suspicious_interpreters:
            if interp in fname:
                interpreter_found = True
                break

        for path in suspicious_paths:
            if path in fpath:
                writable_path_found = True
                break

    # Require reinforcing signals
    if interpreter_found and writable_path_found:
        return 0.75

    return 0.0

def context(event):
    device = event.get("device", {})
    host = device.get("hostname", "unknown host")
    user = event.get("user_principal") or event.get("user_name")
    src_ip = device.get("external_ip") or device.get("local_ip")
    desc = event.get("description", "")

    files_written = event.get("files_written", [])
    if not files_written:
        return desc

    suspicious_interpreters = [
        "python",
        "pythonw",
        "node",
        "deno",
        "esbuild",
        "powershell"
    ]

    suspicious_paths = [
        "\\appdata\\local\\",
        "\\appdata\\roaming\\",
        "\\users\\public\\",
        "\\.tmp",
        "\\."
    ]

    interpreter_found = False
    writable_path_found = False
    file_names = []

    for f in files_written:
        fname = f.get("filename", "").lower()
        fpath = f.get("filepath", "").lower()

        if fname:
            file_names.append(fname)

        for interp in suspicious_interpreters:
            if interp in fname:
                interpreter_found = True
                break

        for path in suspicious_paths:
            if path in fpath:
                writable_path_found = True
                break

    if not (interpreter_found and writable_path_found):
        return desc

    summary = "Suspicious tooling was staged on disk"

    summary += " on host " + host

    if user:
        summary += " under user " + user

    if src_ip:
        summary += " from source IP " + src_ip

    summary += ". "

    if file_names:
        summary += (
            "The process wrote interpreter or tooling binaries including "
            + ", ".join(file_names[:5])
            + "."
        )

    return summary

def criticality():
    return "High"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Masquerading (T1036)"

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

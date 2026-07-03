import json
import time
import calendar
from datetime import datetime, timedelta
from unicodedata import normalize
import re
POWERSHELL_EVENT_IDS = set([4688])



def init(event):
    session.set('parsedlogs',parse(event))
    return 'initialized'


def criteria(meta):
    return (
        meta.get('provider') == 'Microsoft' and
        meta.get('group') == 'Windows' and
        meta.get('type') == 'Audit'
    )

def drop(event):
    if (
        event.get("EventID") in POWERSHELL_EVENT_IDS
    ):
        return False

    return True


def timestamp(event):
    datestring = event.get("EventTime")
    dt_ist = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")
    dt_utc = dt_ist - timedelta(hours=5, minutes=30)

    epoch_time = calendar.timegm(dt_utc.timetuple())
    return int(epoch_time * 1000)


def message(event):
    parseevent = session.get("parsedlogs")

    host = event.get("Hostname")
    user = event.get("SubjectUserName")
    domain = event.get("SubjectDomainName")

    process = event.get("NewProcessName")
    process_id = event.get("NewProcessId")

    parent = (
        event.get("ParentProcessName")
        or event.get("CreatorProcessName")
    )

    logon_id = event.get("SubjectLogonId")

    cmd = None

    try:
        proc_info = parseevent.get("Message", {}).get("processcommandline", {})
        cmd = proc_info.get("values")
    except Exception:
        pass

    parts = []

    parts.append("Process creation detected")

    if process:
        parts.append("for process '{}'".format(process))

    if process_id:
        parts.append("(PID {})".format(process_id))

    if parent:
        parts.append("spawned by '{}'".format(parent))

    if user:
        if domain:
            parts.append("executed under account '{}\\{}'".format(domain, user))
        else:
            parts.append("executed under account '{}'".format(user))

    if logon_id:
        parts.append("with logon session '{}'".format(logon_id))

    if host:
        parts.append("on host '{}'".format(host))

    if cmd:
        parts.append("using command line '{}'".format(cmd[0]))

    return " ".join(parts) + "."

def dictionary(event):
    parsedevent =session.get("parsedlogs")

    FIELD_MAP = {
        # Event
        "event_id": "EventID",

        # Host
        "host": "Hostname",

        # User
        "source_account_name": "SubjectUserName",
        "source_account_domain": "SubjectDomainName",
        "source_account_sid": "SubjectUserSid",
        "source_logon_id": "SubjectLogonId",

        # Process
        "process_name": "NewProcessName",
        "process_id": "NewProcessId",
        "parent_process_name": "ParentProcessName",

        # Environment
        "jumpserver": "jumpserver"
    }

    event_dict = {}

    for dest, src in FIELD_MAP.items():
        value = event.get(src)

        if value not in (None, "", "-", "null"):
            event_dict[dest] = value

    if "event_id" in event_dict:
        event_dict["event_id"] = str(event_dict["event_id"])

    # Extract command line from parsed message
    try:
        msg_obj = parsedevent.get("Message") or {}

        proc_info = msg_obj.get("processcommandline", {})
        cmd = proc_info.get("values")

        if cmd and cmd not in ("-", ""):
            event_dict["command_line"] = cmd[0]

    except Exception:
        pass

    return event_dict



def parse_windows_message(message):
    try:
        message = message.encode('utf-8').decode('unicode_escape')
    except Exception:
        pass

    lines = message.split("\n")

    log_map = {}
    current_section = "header" 
    log_map[current_section] = {}

    counter = 0

    for line in lines:
        if not line.rstrip():
            continue

        line = line.rstrip()

        if line.endswith(":"):
            current_section = line[:-1].strip().lower().replace(" ", "")
            log_map[current_section] = {}
        else:
            line = normalize('NFKD', line)
            try:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace(" ", "_")
                    value = parts[1].strip()
                    log_map[current_section][key] = value
                else:
                    log_map[current_section].setdefault("values", []).append(line)
            except:
                log_map[current_section].setdefault("values", []).append(line)

        counter += 1

    return log_map
def parse(data):
    msg = data.get("Message")

    # Parse the Windows event message
    parsed_message = parse_windows_message(msg)

    # Add the original raw message
    parsed_message["raw_message"] = msg

    # Replace message field with parsed message
    data["Message"] = parsed_message

    return data
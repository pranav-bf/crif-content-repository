import json
import time
import calendar
from datetime import datetime, timedelta
from unicodedata import normalize
import re
AUTH_EVENT_IDS = set([4689,  4697,4698, 4702, 7045 ])



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
    if event.get("EventID") in AUTH_EVENT_IDS:
      return False
    else:
      return True


def timestamp(event):
    datestring = event.get("EventTime")
    dt_ist = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")
    dt_utc = dt_ist - timedelta(hours=5, minutes=30)

    epoch_time = calendar.timegm(dt_utc.timetuple())
    return int(epoch_time * 1000)


def message(event):
    event_id = event.get("EventID")
    host = event.get("Hostname")
    user = event.get("SubjectUserName")
    process = event.get("ProcessName")
    command = event.get("CommandLine")
    service = event.get("ServiceName")

    parts = []

    # --- What happened ---
    if event_id == 4688:
        parts.append("a new process was created")
    elif event_id == 4689:
        parts.append("a process was terminated")
    elif event_id == 4697:
        parts.append("a new service was installed")
    elif event_id == 4698:
        parts.append("a scheduled task was created")
    elif event_id == 4702:
        parts.append("a scheduled task was updated")
    elif event_id == 7045:
        parts.append("a new service was installed (system)")
    else:
        parts.append("a process or persistence-related event occurred")

    # --- Who ---
    if user:
        parts.append("by '{}'".format(user))

    # --- Process / Service ---
    if process:
        parts.append("process '{}'".format(process))
    if service:
        parts.append("service '{}'".format(service))

    # --- Command line ---
    if command:
        parts.append("with command '{}'".format(command))

    # --- Host ---
    if host:
        parts.append("on host {}".format(host))

    return " ".join(parts) + "."

def dictionary(event):
    events = session.get('parsedlogs')
    FIELD_MAP = {
        "event_id": "EventID",
        "host": "Hostname",
        "jumpserver": "jumpserver",

        # actor
        "source_account_name": "SubjectUserName",

        # process info
        "process_name": "ProcessName",
        "command_line": "CommandLine",
        "parent_process_name": "ParentProcessName",

        # service / task
        "service_name": "ServiceName",
        "task_name":"TaskName",
        "task_content":"TaskContent",
        "source_logon_id":"SubjectLogonId",
       "source_account_sid":"SubjectUserSid"
    }

    event_dict = {}

    for dest, src in FIELD_MAP.items():
        value = events.get(src)
        if value is not None:
            event_dict[dest] = value
    if "event_id" in event_dict:
        event_dict["event_id"] = str(event_dict["event_id"])


    return event_dict



def parse_windows_message(message):
    try:
      message = message.encode('utf-8').decode('unicode_escape')
    except Exception:
      pass  # ignore bad escape sequences
    # Split the message into lines
    lines = message.split("\n")

    # Initialize variables
    log_map = {}
    current_section = None
    counter = 0

    # Iterate over each line in the message
    for line in lines:
        # Skip empty lines
        if not line.rstrip():
            continue

        # Remove trailing whitespace from the line
        line = line.rstrip()

        # Parse the header section (first non-empty line)
        if counter == 0:
            pass

        # Parse other sections of the message
        else:
            if line.endswith(":"):
                # If the line ends with a colon, it indicates the start of a new section
                current_section = line[:-1].strip().lower().replace(" ", "")
                log_map[current_section] = {}
            else:
                # If the line does not end with a colon, it contains key-value pairs
                # Split the line into key and value, and add them to the current section
                if current_section is None:
                    current_section = 'header'

                line = normalize('NFKD', line).encode('ascii','ignore')
                try:
                    key, value = map(str.strip, line.split(":", 1))
                    log_map[current_section][key.lower().replace(" ", "_")] = value
                except:
                    # Handle lines that cannot be split into key-value pairs
                    _stripped = line.strip()
                    if len(_stripped) > 0:
                        if log_map[current_section].get('values') is None:
                            log_map[current_section]['values'] = [_stripped]
                        else:
                            log_map[current_section]['values'].append(_stripped)

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
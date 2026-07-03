import json
import time
import calendar
from datetime import datetime, timedelta
from unicodedata import normalize
import re
AUTH_EVENT_IDS = set([4624, 4625,4626 ,4648,4964,4800, 4801,4802,4803])



def init(event):

    return 'initialized'


def criteria(meta):
    return (
          meta.get('provider') == 'Microsoft' and
          meta.get('group') == 'Windows' and
          meta.get('type') == 'Audit'
      )

def drop(event):
    if  event.get("EventID") in AUTH_EVENT_IDS:
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
    host = event.get("Hostname")
    event_id = event.get("EventID")
    user = event.get("TargetUserName") or event.get("SubjectUserName")
    src_ip = event.get("IpAddress")
    logon_type = event.get("LogonType")

    parts = []

    # --- What happened (core meaning) ---
    if event_id == 4624:
        parts.append("a successful logon occurred")
    elif event_id == 4625:
        parts.append("a failed logon attempt was detected")
    elif event_id == 4648:
        parts.append("a logon using explicit credentials was attempted")
    elif event_id == 4776:
        parts.append("an NTLM authentication attempt occurred")
    elif event_id == 4778:
        parts.append("an RDP session was reconnected")
    elif event_id == 4779:
        parts.append("an RDP session was disconnected")
    else:
        parts.append("an authentication-related event occurred")

    # --- Who ---
    if user:
        parts.append("for user '{}'".format(user))

    # --- From where ---
    if src_ip:
        parts.append("from IP {}".format(src_ip))

    # --- Where ---
    if host:
        parts.append("on host {}".format(host))

    # --- How ---
    if logon_type:
        parts.append("using logon type {}".format(logon_type))

    return " ".join(parts) + "."

def dictionary(event):
    events = parse(event)
    msg = events.get("Message") or {}

    subject = msg.get("subject") or {}
    target = (
        msg.get("accountforwhichlogonfailed") or
        msg.get("newlogon") or
        {}
    )
    netinfo = msg.get("networkinformation") or {}
    logoninfo = msg.get("logoninformation") or {}
    authinfo = msg.get("detailedauthenticationinformation") or {}
    procinfo = msg.get("processinformation") or {}
    failureinfo = msg.get("failureinformation") or {}

    # 👤 identity
    source_user = subject.get("account_name") or event.get("SubjectUserName") or "UNKNOWN"
    target_user = target.get("account_name") or event.get("TargetUserName") or "UNKNOWN"

    # 🌐 network
    source_ip = netinfo.get("source_network_address") or event.get("IpAddress") or "UNKNOWN"
    if source_ip in ("-", "", "_"):
        source_ip = "UNKNOWN"

    workstation = netinfo.get("workstation_name") or event.get("WorkstationName") or "UNKNOWN"

    # 🔐 auth
    logon_type = logoninfo.get("logon_type") or event.get("LogonType") or "UNKNOWN"
    status = failureinfo.get("status") or event.get("Status") or "UNKNOWN"
    sub_status = failureinfo.get("sub_status") or event.get("SubStatus") or "UNKNOWN"
    failure_reason = failureinfo.get("failure_reason") or event.get("FailureReason") or "UNKNOWN"

    return {
        # 🔹 core
        "event_id": str(event.get("EventID") or ""),
        "event_type": event.get("EventType") or "UNKNOWN",
        "host": event.get("Hostname") or "UNKNOWN",
        "event_channel": event.get("Channel") or "UNKNOWN",
        "event_level": event.get("Severity") or "UNKNOWN",
        "jumpserver": event.get("jumpserver"),

        # 👤 identity
        "source_account_name": source_user,
        "source_account_sid": event.get("SubjectUserSid") or "UNKNOWN",
        "destination_account_name": target_user,
        "destination_account_sid": event.get("TargetUserSid") or "UNKNOWN",

        # 🌐 network
        "source_ip": source_ip,
        "source_workstation": workstation,

        # 🔐 auth
        "logon_type": str(logon_type),
        "auth_package": authinfo.get("authentication_package") or event.get("AuthenticationPackageName") or "UNKNOWN",
        "source_logon_id": event.get("SubjectLogonId") or "UNKNOWN",

        # ⚙️ process
        "process_name": event.get("ProcessName") or procinfo.get("caller_process_name") or "UNKNOWN",
        "process_id": str(event.get("ProcessID") or "UNKNOWN"),

        # ❗ failure (generic mapping)
        "status": status,
        "sub_status": sub_status,
        "event_status": failure_reason,
    }



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

                line = normalize('NFKD', line)
                try:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        key = parts[0].strip().lower().replace(" ", "_")
                        value = parts[1].strip()
                        log_map[current_section][key] = value
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
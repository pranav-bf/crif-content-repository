import json
import time
import calendar
from datetime import datetime, timedelta
import re
INTEGRITY_EVENT_IDS = set([1102, 4719,805, 808, 4656,13, 11 ])



def init(event):
  return "initialization completed"


def criteria(meta):
    return (
        meta.get('provider') == 'Microsoft' and
        meta.get('group') == 'Windows' and
        meta.get('type') == 'Audit'
    )

def drop(event):

    msg = (event.get("Message") or "").lower()
    match = re.search(r"cn=([^']+)", msg)
    cn_value=""
    if match:
        cn_value = match.group(1)
    if (event.get("EventID") in INTEGRITY_EVENT_IDS and "adfs" not in cn_value):
        return False

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
    object_name = event.get("ObjectName")
    registry = event.get("TargetObject")
    process = event.get("ProcessName")

    parts = []

    # --- What happened ---
    if event_id == 1102:
        parts.append("the security audit log was cleared")
    elif event_id == 4719:
        parts.append("system audit policy was changed")
    elif event_id in [805, 808]:
        parts.append("printer configuration was modified or exploited")
    elif event_id == 13:
        parts.append("a registry value was modified")
    elif event_id == 11:
        parts.append("a file was created")
    else:
        parts.append("a system integrity-related event occurred")

    # --- Who ---
    if user:
        parts.append("by '{}'".format(user))

    # --- Object / Registry ---
    if object_name:
        parts.append("on object '{}'".format(object_name))
    if registry:
        parts.append("registry path '{}'".format(registry))

    # --- Process ---
    if process:
        parts.append("via process '{}'".format(process))

    # --- Host ---
    if host:
        parts.append("on host {}".format(host))

    return " ".join(parts) + "."

def dictionary(event):

    FIELD_MAP = {
        "event_id": "EventID",
        "host": "Hostname",
        "jumpserver": "jumpserver",

        # actor
        "source_account_name": "SubjectUserName",
      "source_account_sid":"SubjectUserSid",
      "source_account_domain":"SubjectDomainName",

        # object/file
        #"object_name": "ObjectName",
        "file_path": "ObjectName",

        # registry
        "registry_path": "TargetObject",

        # process
        "process_name": "ProcessName",

        # access context
        "access_mask_hex": "AccessMask",
        "share_name": "ShareName",
"share_path": "SharePath",
"target_relative_path": "RelativeTargetName"
    }

    event_dict = {}

    for dest, src in FIELD_MAP.items():
        value = event.get(src)
        if value is None:
            continue
        event_dict[dest] = value

    if "event_id" in event_dict:
        event_dict["event_id"] = str(event_dict["event_id"])

    return event_dict



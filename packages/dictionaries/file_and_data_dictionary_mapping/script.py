import json
import calendar
from datetime import datetime, timedelta
NETWORK_EVENT_IDS = set([
  5140, 5145,        # SMB
    5156, 5157,        # WFP network
    22,                # Sysmon DNS
    3006, 3008 ,        # DNS logs
  4660,4663
])



def init(event):
  return "initialization completed"


def criteria(meta):
    return (
        meta.get('provider') == 'Microsoft' and
        meta.get('group') == 'Windows'and
        meta.get('type') == 'Audit'
    )

def drop(event):
    if event.get("EventID") in NETWORK_EVENT_IDS:
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
    src_ip = event.get("SourceAddress") or event.get("IpAddress")
    dest_ip = event.get("DestAddress")
    dest_port = event.get("DestPort")
    share = event.get("ShareName")
    dns_query = event.get("QueryName")

    parts = []

    # --- What happened ---
    if event_id == 5140:
        parts.append("a network share was accessed")
    elif event_id == 5145:
        parts.append("a detailed SMB share access occurred")
    elif event_id == 5156:
        parts.append("a network connection was allowed")
    elif event_id == 5157:
        parts.append("a network connection was blocked")
    elif event_id == 22:
        parts.append("a DNS query was performed")
    elif event_id in [4663, 4660]:
        parts.append("a file or object was accessed or deleted")
    elif event_id in [3006, 3008]:
        parts.append("a DNS request/response was recorded")
    else:
        parts.append("a network-related event occurred")

    # --- Source ---
    if src_ip:
        parts.append("from IP {}".format(src_ip))

    # --- Destination ---
    if dest_ip:
        parts.append("to IP {}".format(dest_ip))
    if dest_port:
        parts.append("on port {}".format(dest_port))

    # --- SMB ---
    if share:
        parts.append("accessing share '{}'".format(share))

    # --- DNS ---
    if dns_query:
        parts.append("for domain '{}'".format(dns_query))

    # --- Host ---
    if host:
        parts.append("on host {}".format(host))

    return " ".join(parts) + "."

def dictionary(event):
    FIELD_MAP = {
        "event_id": "EventID",
        "host": "Hostname",
        "jumpserver": "jumpserver",

        # source
        "source_ip": "SourceAddress",
        
        # destination
        "destination_ip": "DestAddress",
        "destination_port": "DestPort",

        # SMB
        "share_name": "ShareName",
        "file_path": "RelativeTargetName",

        # DNS
        "query_name": "QueryName",

        "source_account_domain":"SubjectDomainName",

        # object/file
        #"object_name": "ObjectName",
        "file_path": "ObjectName",

          # actor
        "source_account_name": "SubjectUserName",
      "source_account_sid":"SubjectUserSid",
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



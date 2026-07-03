import json
import time
import calendar
from datetime import datetime, timedelta
from unicodedata import normalize
import re
ADFS_EVENT_IDS = set([299,403,410,411,412,500,501,510,1200,1203])



def init(event):
#Define initialize steps  and its attributes
    session.set('parsedlogs',parse(event))
    return 'initialized'


def criteria(meta):
      return (
        meta.get('provider') == 'Microsoft' and
        meta.get('group') == 'Windows' and
        meta.get('type') == 'Audit'
    )

def drop(event):
    if  event.get("EventID") in ADFS_EVENT_IDS:
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
    parsed = session.get("parsedlogs")

    host = event.get("Hostname")
    event_id = event.get("EventID")
    source_ip = event.get("IpAddress") or event.get("ClientIpAddress")
    username = event.get("UserId") or event.get("UserName")
    proxy = event.get("ProxyServer")
    url_path = event.get("UrlPath")
    user_agent = event.get("UserAgent")

    parts = []

    parts.append("AD FS event '{}' detected".format(event_id))

    if host:
        parts.append("on host '{}'".format(host))

    if username:
        parts.append("for user '{}'".format(username))

    if source_ip:
        parts.append("from source IP '{}'".format(source_ip))

    if proxy:
        parts.append("through proxy '{}'".format(proxy))

    if url_path:
        parts.append("targeting '{}'".format(url_path))

    if user_agent:
        parts.append("using User-Agent '{}'".format(user_agent))

    return " ".join(parts) + "."

def dictionary(event):
    parsed = session.get("parsedlogs")

    FIELD_MAP = {
        "event_id": "EventID",
        "host": "Hostname",
        "source_ip": "IpAddress",
        "source_account_name": "UserId",
        "proxy_server": "ProxyServer",
        "url_path": "UrlPath",
        "user_agent": "UserAgent",
        "activity_id": "ActivityId",
        "instance_id": "InstanceId",
        "jumpserver": "jumpserver",
    }

    event_dict = {}

    for dest, src in FIELD_MAP.items():
        value = event.get(src)

        if value not in (None, "", "-", "null"):
            event_dict[dest] = value

    # Alternate client IP field
    if "source_ip" not in event_dict:
        client_ip = event.get("ClientIpAddress")
        if client_ip:
            event_dict["source_ip"] = client_ip

    # Alternate username field
    if "source_account_name" not in event_dict:
        user = event.get("UserName")
        if user:
            event_dict["source_account_name"] = user

    if "event_id" in event_dict:
        event_dict["event_id"] = str(event_dict["event_id"])

    return event_dict



def parse_windows_message(message):
    message = message.encode('utf-8').decode('unicode_escape')
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
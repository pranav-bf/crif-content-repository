import json
import time
import calendar
from datetime import datetime, timedelta
from unicodedata import normalize
import re
AUTH_EVENT_IDS = set([
        4720, 4722, 4725, 4726,
        4728, 4732, 4756,
        4672
    ])



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
    event_id = str(event.get("EventID") or "")

    actor = event.get("SubjectUserName")
    member = event.get("MemberName")
    target = event.get("TargetUserName")
    host = event.get("Hostname")

    parts = []

    if event_id == "4720":

        parts.append("User account created")

        if target:
            parts.append("account '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4722":

        parts.append("User account enabled")

        if target:
            parts.append("account '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4725":

        parts.append("User account disabled")

        if target:
            parts.append("account '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4726":

        parts.append("User account deleted")

        if target:
            parts.append("account '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4728":

        parts.append("Member added to security-enabled global group")

        if member:
            parts.append("member '{}'".format(member))

        if target:
            parts.append("added to group '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4732":

        parts.append("Member added to security-enabled local group")

        if member:
            parts.append("member '{}'".format(member))

        if target:
            parts.append("added to group '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4756":

        parts.append("Member added to security-enabled universal group")

        if member:
            parts.append("member '{}'".format(member))

        if target:
            parts.append("added to group '{}'".format(target))

        if actor:
            parts.append("by '{}'".format(actor))

    elif event_id == "4672":

        parts.append("Special privileges assigned during logon")

        if actor:
            parts.append("to account '{}'".format(actor))

    else:

        parts.append("Identity management activity detected")

        if actor:
            parts.append("by '{}'".format(actor))

    if host:
        parts.append("on host '{}'".format(host))

    return " ".join(parts) + "."

def dictionary(event):

    FIELD_MAP = {
        "event_id": "EventID",
        "host": "Hostname",
        "jumpserver": "jumpserver",

        "source_account_name": "SubjectUserName",
     
        "source_account_domain":"SubjectDomainName",
         "source_account_sid": "SubjectUserSid",
        "source_logon_id": "SubjectLogonId",


       "destination_group_name": "TargetUserName",
       "member_name":"MemberName",

        "access_list_raw": "AccessList",


    }

    event_dict = {}

    for dest, src in FIELD_MAP.items():
        value = event.get(src)
        if value is not None:
            event_dict[dest] = value

    if "event_id" in event_dict:
      event_dict["event_id"] = str(event_dict["event_id"])

    if "PrivilegeList" in event:
      priv = event.get("PrivilegeList")

      if isinstance(priv, basestring):
          # handle different formats: space, comma, semicolon
          cleaned = priv.replace(",", " ").replace(";", " ")
          event_dict["privileges"] = [p for p in cleaned.split() if p]
  
      elif isinstance(priv, list):
          event_dict["privileges"] = priv

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
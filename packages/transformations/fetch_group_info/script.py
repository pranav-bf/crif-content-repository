import time
from datetime import datetime
from unicodedata import normalize
import re
import json



def transform(event):
    if "Group" not in event.get("details"):
        return event
    data=parse(event)
    Message=data.get("Message")
    event["member_name"]=Message.get("Member").get("security_id")
    event["destination_group_name"]=Message.get("Group").get("group_name")
    if "details" in event:
        del event["details"]

    

    return event


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
    msg = data.get("details")
    if not msg:
        # If no message present, return as-is
        log["data"] = data
        log["data"]["parse_status"] = "missing_message"
        return log

    # Parse the Windows event message
    parsed_message = parse_windows_message(msg)

    # Add the original raw message
    parsed_message["raw_message"] = msg

    # Replace message field with parsed message
    data["Message"] = parsed_message

    # Optional: Add parse success indicator
    data["parse_status"] = "success"

    return data
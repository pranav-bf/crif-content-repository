from datetime import datetime
import calendar



def init(event):
#Define initialize steps  and its attributes
    return "initialization completed"


def criteria(meta):
  return True

def drop(event):
# 5. Drop based on specific action
    if event.get("action") == "allowed":
        return True

    # Default → keep event
    return False


def timestamp(event):

    ts = event.get("timestamp")

    if not ts:
        return None

    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return calendar.timegm(dt.utctimetuple()) * 1000
    except:
        return None


def message(event):
    action = event.get("act") or event.get("name") or "Unknown Event"
    user = event.get("suser") or "Unknown User"

    host = (
        event.get("dst")
        or event.get("dhost")
        or event.get("shost")
        or "Unknown Host"
    )

    return "{} by {} on {}".format(action, user, host)

def dictionary(event):
    out = {}



    out["event_name"] = event.get("name")
    out["event_action"] = event.get("act")
    out["event_id"] = event.get("signature_id")
    out["event_severity"] = event.get("severity")



    out["username"] = event.get("suser")
    out["target_username"] = event.get("duser")



    out["source_ip"] = event.get("src") or event.get("shost")
    out["destination_ip"] = event.get("dst") or event.get("dhost")
    out["device_ip"] = event.get("dvc")

    out["session_id"] = None
    out["session_type"] = None
    out["connection_protocol"] = None
    out["destination_host"] = event.get("dhost") or event.get("dst")
    out["source_host"] = event.get("shost") or event.get("src")


    out["application"] = event.get("app")
    out["reason"] = event.get("reason")
    out["request_id"] = None
    out["ticket_id"] = None


    for i in range(1, 6):

        label = event.get("cs{}Label".format(i))
        value = event.get("cs{}".format(i))

        if not label:
            continue

        label = label.lower().replace(" ", "_")

        if label == "session_id":
            out["session_id"] = value

        elif label == "session_type":
            out["session_type"] = value

        elif label == "connection_protocol":
            out["connection_protocol"] = value

        elif label == "target_machine":
            out["destination_host"] = value

        elif label == "other_info":
            out["other_info"] = value


    for i in range(1, 3):

        label = event.get("cn{}Label".format(i))
        value = event.get("cn{}".format(i))

        if not label:
            continue

        label = label.lower().replace(" ", "_")

        if label == "request_id":
            out["request_id"] = value

        elif label == "ticket_id":
            out["ticket_id"] = value



    out["message"] = event.get("msg")

    return out 



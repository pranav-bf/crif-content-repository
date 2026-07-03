from datetime import datetime
import calendar



def init(event):
    return "initialization completed"


def criteria(meta):
    return (
        meta["provider"] == "Microsoft"
        and meta["group"] == "Windows Events"
        and meta["type"] == "Audit"
    )

def drop(event):
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
    target_user = event.get("duser")

    safe = None

    for i in range(1, 6):
        if event.get("cs{}Label".format(i)) == "Safe Name":
            safe = event.get("cs{}".format(i))
            break

    # Preserve important vendor context
    vendor_msg = (event.get("msg") or "").lower()

    if "copy password" in vendor_msg:
        action += " (Copy Password)"

    message = "{} by {}".format(action, user)

    if target_user:
        message += " for account '{}'".format(target_user)

    if safe:
        message += " on Safe '{}'".format(safe)

    return message

def dictionary(event):

    out = {}



    out["event"] = event.get("name")
    out["event_action"] = event.get("act")
    out["event_id"] = event.get("signature_id")
    out["event_severity"] = event.get("severity")


    out["user_name"] = event.get("suser")
    out["target_user"] = event.get("duser")



    out["source_ip"] = event.get("src") or event.get("shost")
    out["destination_ip"] = event.get("dst") or event.get("dhost")


    out["applicationname"] = event.get("app")
    out["event.reason"] = event.get("reason")
    out["request_id"] = None
    out["ticket_id"] = None



    for i in range(1, 6):

        label = event.get("cs{}Label".format(i))
        value = event.get("cs{}".format(i))

        if not label:
            continue

        label = label.lower().replace(" ", "_")

        if label == "device_type":
            out["device_type"] = value


        elif label == "database":
            out["dbname"] = value





    for i in range(1, 3):

        label = event.get("cn{}Label".format(i))
        value = event.get("cn{}".format(i))

        if not label:
            continue

        label = label.lower().replace(" ", "_")

        if label == "request_id":
            out["token_request_id"] = value

  

    out["message"] = event.get("msg")

    return out



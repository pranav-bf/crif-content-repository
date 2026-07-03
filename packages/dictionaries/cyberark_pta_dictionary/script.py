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
    action = event.get("name") or event.get("act") or "Unknown Event"
    actor = event.get("suser") or "Unknown User"
    target = event.get("duser")

    safe = None

    for i in range(1, 6):
        if event.get("cs{}Label".format(i)) == "Safe Name":
            safe = event.get("cs{}".format(i))
            break

    parts = [
        action,
        "by {}".format(actor)
    ]

    if target:
        parts.append("for account '{}'".format(target))

    if safe:
        parts.append("on Safe '{}'".format(safe))

    return " ".join(parts)

def dictionary(event):

    out = {}



    out["event_name"] = event.get("name")
    out["event_action"] = event.get("act")
    out["event_id"] = event.get("signature_id")
    out["event_severity"] = event.get("severity")


    out["user_name"] = event.get("suser")
    out["target_user"] = event.get("duser")

    out["source_hostname"] = event.get("shost")
    out["destination_hostname"] = event.get("dhost")



    out["source_ip"] = event.get("src")
    out["destination_ip"] = event.get("dst")
    out["device_ip"] = event.get("dvc")


    out["applicationname"] = event.get("app")
    out["reason"] = event.get("reason")
    out["request_id"] = None
    out["ticket_id"] = None



    for i in range(1, 6):

        label = event.get("cs{}Label".format(i))
        value = event.get("cs{}".format(i))

        if not label:
            continue

        label = label.lower().replace(" ", "_")

        if label == "safe_name":
            out["safe_name"] = value

        elif label == "affected_user_name":
            out["affected_user"] = value

        elif label == "device_type":
            out["device_type"] = value

        elif label == "database":
            out["database"] = value

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



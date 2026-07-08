from datetime import datetime
import calendar
import re


_IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)


def init(event):
    return "initialization completed"


def criteria(meta):
    return (
        meta["provider"] == "CyberArk"
        and meta["group"] == "PAM"
        and meta["type"] == "Vault"
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


def is_ip(value):

    if not value:
        return False

    value = str(value).strip()

    return _IPV4_REGEX.match(value) is not None


def message(event):

    action = event.get("act") or event.get("name") or "Unknown Event"
    user = event.get("suser") or "Unknown User"
    target_user = event.get("duser")

    safe = None

    for i in range(1, 6):
        if event.get("cs{}Label".format(i)) == "Safe Name":
            safe = event.get("cs{}".format(i))
            break

    vendor_name = (event.get("name") or "").lower()
    vendor_msg = (event.get("msg") or "").lower()

    if "copy password" in vendor_msg:
        action += " (Copy Password)"

    elif "failure" in vendor_name:
        action = "Failed " + action

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

    # Network mapping
    src = event.get("src") or event.get("shost")

    if src:
        if is_ip(src):
            out["source_ip"] = src
        else:
            out["source_hostname"] = src

    dst = event.get("dst") or event.get("dhost")

    if dst:
        if is_ip(dst):
            out["destination_ip"] = dst
        else:
            out["destination_hostname"] = dst

    out["applicationname"] = event.get("app")
    out["event_reason"] = event.get("reason")
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

        elif label == "safe_name":
            out["safe_name"] = value

    for i in range(1, 3):

        label = event.get("cn{}Label".format(i))
        value = event.get("cn{}".format(i))

        if not label:
            continue

        label = label.lower().replace(" ", "_")

        if label == "request_id":
            out["token_request_id"] = value

    out["message"] = message(event)

    return out
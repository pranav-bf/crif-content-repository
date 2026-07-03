import calendar
from datetime import datetime, timedelta



def init(event):
  return "initialization completed"


def criteria(meta):
    return (
        meta.get('provider') == 'Fortinet' and
        meta.get('group') == 'FortiGate' and
        meta.get('type') == 'Firewall'
    )

def drop(event):
    log = event.get("type")
    subtype = event.get("subtype")
    if log == 'event' and subtype == "user":
        return False
    else:
        return True


def timestamp(event):
    d, t = event.get("date"), event.get("time")
    IST_OFFSET = timedelta(hours=5, minutes=30)
    if not d or not t:
        return None
    try:
        dt = datetime.strptime("%s %s" % (d, t), "%Y-%m-%d %H:%M:%S")
        return int(calendar.timegm((dt - IST_OFFSET).timetuple()) * 1000)
    except:
        return None


def message(event):
    parts = []

    if event.get("action"):
        parts.append("Firewall action for user event %s" % event.get("action"))
    else:
        parts.append("Firewall event")

    if event.get("srcip"):
        src = event.get("srcip")
        if event.get("srcport"):
            parts.append("from %s:%s" % (src, event.get("srcport")))
        else:
            parts.append("from %s" % src)

    if event.get("dstip"):
        dst = event.get("dstip")
        if event.get("dstport"):
            parts.append("to %s:%s" % (dst, event.get("dstport")))
        else:
            parts.append("to %s" % dst)

    if event.get("devname"):
        parts.append("on device %s" % event.get("devname"))

    if event.get("user"):
        parts.append("where user involved is %s" % event.get("user"))

    if event.get("logdesc"):
        parts.append("indicating alert %s" % event.get("logdesc"))

    if event.get("msg"):
        parts.append("and further details '%s'" % event.get("msg"))

    return " ".join(parts) + "."

def dictionary(event):
    result = {}

    if event.get("dstport") or event.get("remport"):
        result["destination_port"] = str(event.get("dstport") or event.get("remport"))

    if event.get("srcip") or event.get("locip"):
        result["source_ip"] = str(event.get("srcip") or event.get("locip"))

    if event.get("dstip") or event.get("remip"):
        result["destination_ip"] = str(event.get("dstip") or event.get("remip"))

    if event.get("attack") or event.get("logdesc"):
        result["event"] = str(event.get("attack") or event.get("logdesc"))

    if event.get("action"):
        result["event_action"] = event.get("action")

    if event.get("devname"):
        result["source_device_name"] = event.get("devname")

    if event.get("user"):
        result["user_name"] = str(event.get("user"))

    if event.get("msg"):
        result["event_details"] = str(event.get("msg"))

    if event.get("service"):
        result["network_protocol"] = str(event.get("service"))

    if event.get("type"):
        result["log_type"] = event.get("type")

    if event.get("subtype"):
        result["log_subtype"] = event.get("subtype")

    if event.get("app"):
        result["applicationname"] = event.get("app")

    if event.get("jumpserver"):
        result["jumpserver"] = event.get("jumpserver")

    return result



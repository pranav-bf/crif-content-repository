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
    if log == 'event' and subtype == "system":
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
        parts.append("Firewall action for system event '%s'" % event.get("action"))
    else:
        parts.append("Firewall event")

    if event.get("dstip") or event.get("remip"):
        parts.append("where destination IP %s" % (event.get("dstip") or event.get("remip")))

    if event.get("devname") or event.get("ui"):
        parts.append("from device '%s'" % (event.get("devname") or event.get("ui")))

    if event.get("user"):
        parts.append("involving user '%s'" % event.get("user"))

    if event.get("subtype"):
        parts.append("with subtype '%s'" % event.get("subtype"))

    if event.get("logdesc"):
        parts.append("event '%s'" % event.get("logdesc"))

    if event.get("reason") or event.get("attack"):
        parts.append("alert '%s'" % (event.get("reason") or event.get("attack")))

    if event.get("severity"):
        parts.append("severity '%s'" % event.get("severity"))

    if event.get("msg"):
        parts.append("details '%s'" % event.get("msg"))

    return " ".join(parts) + "."

def dictionary(event):
    result = {}

    if event.get("dstip") or event.get("remip"):
        result["destination_ip"] = str(event.get("dstip") or event.get("remip"))

    if event.get("srcip") or event.get("locip"):
        result["source_ip"] = str(event.get("srcip") or event.get("locip"))
      
    if event.get("attack") or event.get("logdesc"):
        result["event"] = str(event.get("attack") or event.get("logdesc"))

    if event.get("action"):
        result["event_action"] = event.get("action")

    if event.get("severity"):
        result["event_severity"] = event.get("severity")

    if event.get("reason") or event.get("attack"):
        result["event_alert"] = str(event.get("reason") or event.get("attack"))

    if event.get("devname") or event.get("ui"):
        result["source_device_name"] = event.get("devname") or event.get("ui")

    if event.get("user"):
        result["user_name"] = str(event.get("user"))

    if event.get("type"):
        result["log_type"] = event.get("type")

    if event.get("subtype"):
        result["log_subtype"] = event.get("subtype")

    if event.get("dstintf"):
        result["destination_device_interface"] = str(event.get("dstintf"))

    if event.get("srcintf"):
        result["source_device_interface"] = str(event.get("srcintf"))

    if event.get("msg"):
        result["event_details"] = event.get("msg")

    if event.get("app"):
        result["applicationname"] = event.get("app")

    if event.get("jumpserver"):
        result["jumpserver"] = event.get("jumpserver")

    if event.get("service"):
        result["network_protocol"] = str(event.get("service"))

    return result



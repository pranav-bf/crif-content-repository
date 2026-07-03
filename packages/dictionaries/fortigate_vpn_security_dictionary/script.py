import calendar
from datetime import datetime, timedelta
LOG_LEVELS = {
    "emergency": 0, "alert": 1, "critical": 2,
    "error": 3, "warning": 4, "notice": 5,
    "information": 6, "debug": 7
}



def init(event):
  return "initialization completed"


def criteria(meta):
    return (
        meta.get('provider') == 'Fortinet' and
        meta.get('group') == 'FortiGate' and
        meta.get('type') == 'Firewall'
    )

def drop(event):
    subtype = event.get("subtype")
    if subtype == "vpn":
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

    action = event.get("action")
    if action:
        parts.append("Firewall action for vpn %s" % action)
    else:
        parts.append("Firewall event")

    src = event.get("srcip") or event.get("locip")
    if src:
        src_port = event.get("srcport") or event.get("locport")
        if src_port:
            parts.append("from %s:%s" % (src, src_port))
        else:
            parts.append("from %s" % src)

    dst = event.get("dstip") or event.get("remip")
    if dst:
        dst_port = event.get("dstport") or event.get("remport")
        if dst_port:
            parts.append("to %s:%s" % (dst, dst_port))
        else:
            parts.append("to %s" % dst)

    service = event.get("service")
    if service:
        parts.append("using protocol %s" % service)

    devname = event.get("devname")
    if devname:
        parts.append("on device %s" % devname)

    subtype = event.get("subtype")
    if subtype:
        parts.append("which has subtype %s" % subtype)

    dstcountry = event.get("dstcountry")
    if dstcountry:
        parts.append("destination country %s" % dstcountry)

    srccountry = event.get("srccountry")
    if srccountry:
        parts.append("originating from source country %s" % srccountry)

    tunnel = event.get("using tunneltype")
    if tunnel:
        parts.append("tunnel type %s" % tunnel)

    user = event.get("user")
    if user:
        parts.append("user involved %s" % user)

    level = event.get("level")
    if level:
        parts.append("with severity %s" % level)

    msg = event.get("msg")
    if msg:
        parts.append("and further details '%s'" % msg)

    return " ".join(parts) + "."

def dictionary(event):
    result = {}

    if event.get("dstport") or event.get("remport"):
        result["destination_port"] = str(event.get("dstport") or event.get("remport"))

    if event.get("srcport") or event.get("locport"):
        result["source_port"] = str(event.get("srcport") or event.get("locport"))

    if event.get("srcip") or event.get("locip"):
        result["source_ip"] = str(event.get("srcip") or event.get("locip"))

    if event.get("dstip") or event.get("remip"):
        result["destination_ip"] = str(event.get("dstip") or event.get("remip"))

    if event.get("attack") or event.get("logdesc"):
        result["event"] = (event.get("attack") or event.get("logdesc"))

    if event.get("action"):
        result["event_action"] = event.get("action")

    if event.get("devname"):
        result["source_device_name"] = event.get("devname")

    if event.get("subtype"):
        result["log_subtype"] = event.get("subtype")

    if event.get("dstcountry"):
        result["destination_country"] = event.get("dstcountry")

    if event.get("srccountry"):
        result["source_country"] = event.get("srccountry")

    if event.get("tunneltype"):
        result["tunnel_type"] = event.get("tunneltype")

    if event.get("user"):
        result["user_name"] = str(event.get("user"))

    if event.get("msg"):
        result["event_details"] = str(event.get("msg"))

    if event.get("app"):
        result["applicationname"] = event.get("app")

    if event.get("type"):
        result["log_type"] = event.get("type")

    if event.get("service"):
        result["network_protocol"] = str(event.get("service"))

    if event.get("jumpserver"):
        result["jumpserver"] = event.get("jumpserver")

    if event.get("level"):
        if event.get("level") in LOG_LEVELS:
            result["event_level"] = str(LOG_LEVELS.get(event.get("level")))
        else:
            result["event_level"] = event.get("level")

    return result



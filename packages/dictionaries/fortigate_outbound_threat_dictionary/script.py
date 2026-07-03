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
    dir = event.get("dir") or event.get("direction")
    if log == 'traffic' and dir == "outgoing":
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
        parts.append("Firewall action for outbound traffic '%s'" % event.get("action"))
    else:
        parts.append("Firewall traffic event")

    if event.get("srcip") or event.get("locip"):
        parts.append("from source IP %s" % (event.get("srcip") or event.get("locip")))

    if event.get("dstip") or event.get("remip"):
        parts.append("to destination IP %s" % (event.get("dstip") or event.get("remip")))

    if event.get("dstport") or event.get("remport"):
        parts.append("on port %s" % (event.get("dstport") or event.get("remport")))

    if event.get("service"):
        parts.append("using protocol %s" % event.get("service"))

    if event.get("devname") or event.get("ui"):
        parts.append("via device '%s'" % (event.get("devname") or event.get("ui")))

    if event.get("dstcountry"):
        parts.append("destination country '%s'" % event.get("dstcountry"))

    if event.get("sentbyte"):
        parts.append("bytes sent %s" % event.get("sentbyte"))

    return " ".join(parts) + "."

def dictionary(event):
    result = {}

    if event.get("dstip") or event.get("remip"):
        result["destination_ip"] = str(event.get("dstip") or event.get("remip"))
      
    if event.get("srcip") or event.get("locip"):
        result["source_ip"] = str(event.get("srcip") or event.get("locip"))

    if event.get("dstport") or event.get("remport"):
        result["destination_port"] = str(event.get("dstport") or event.get("remport"))

    if event.get("action"):
        result["event_action"] = event.get("action")

    if event.get("devname") or event.get("ui"):
        result["source_device_name"] = event.get("devname") or event.get("ui")

    if event.get("service"):
        result["network_protocol"] = str(event.get("service"))

    if event.get("dstcountry"):
        result["destination_country"] = event.get("dstcountry")

    if event.get("sentbyte"):
        result["network_bytes_out"] = event.get("sentbyte")

    if event.get("type"):
        result["log_type"] = event.get("type")

    if event.get("subtype"):
        result["log_subtype"] = event.get("subtype")

    if event.get("app"):
        result["applicationname"] = event.get("app")

    if event.get("jumpserver"):
        result["jumpserver"] = event.get("jumpserver")

    return result



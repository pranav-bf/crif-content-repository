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
    if (event.get("type") == "utm" and event.get("subtype") in ["webfilter", "ips", "virus", "anomaly"]):
        return False
    else:
        return True


def timestamp(event):
    d, t = event.get("date"), event.get("time")
    IST_OFFSET = timedelta(hours=5, minutes=30)
    dt = datetime.strptime("%s %s" % (d, t), "%Y-%m-%d %H:%M:%S")
    return int(calendar.timegm((dt - IST_OFFSET).timetuple()) * 1000)


def message(event):
    parts = []

    action = event.get("action")
    if action:
        parts.append("Firewall action for threat %s" % action)
    else:
        parts.append("Firewall event")

    src = event.get("srcip")
    if src:
        src_port = event.get("srcport")
        if src_port:
            parts.append("from %s:%s" % (src, src_port))
        else:
            parts.append("from %s" % src)

    dst = event.get("dstip")
    if dst:
        dst_port = event.get("dstport")
        if dst_port:
            parts.append("to %s:%s" % (dst, dst_port))
        else:
            parts.append("to %s" % dst)

    service = event.get("service")
    if service:
        parts.append("using protocol  %s" % service)

    user = event.get("user")
    if user:
        parts.append("user %s" % user)

    policy = event.get("policyname")
    if policy:
        parts.append("policy '%s'" % policy)

    url = event.get("url")
    if url:
        parts.append("the url accessed is %s" % url)

    app = event.get("app")
    if app:
        parts.append("app %s" % app)

    catdesc = event.get("catdesc")
    if catdesc:
        parts.append("of category %s" % catdesc)

    level = event.get("level")
    if level:
        parts.append("with severity %s" % level)

    msg = event.get("msg")
    if msg:
        parts.append("and further details '%s'" % msg)

    return " ".join(parts) + "."

def dictionary(event):
    result = {}

    if event.get("dstport") is not None:
        result["destination_port"] = str(event.get("dstport"))

    if event.get("action"):
        result["event_action"] = event.get("action")

    if event.get("policyid") is not None:
        result["policy_id"] = str(event.get("policyid"))

    if event.get("service"):
        result["network_protocol"] = str(event.get("service"))

    if event.get("devname"):
        result["source_device_name"] = event.get("devname")

    if event.get("srcip"):
        result["source_ip"] = str(event.get("srcip"))

    if event.get("dstip"):
        result["destination_ip"] = str(event.get("dstip"))

    if event.get("srcport") is not None:
        result["source_port"] = str(event.get("srcport"))

    if event.get("dstcountry"):
        result["destination_country"] = event.get("dstcountry")

    if event.get("type"):
        result["log_type"] = event.get("type")

    if event.get("subtype"):
        result["log_subtype"] = event.get("subtype")

    if event.get("url"):
        result["url"] = event.get("url")

    if event.get("user"):
        result["user_name"] = str(event.get("user"))

    if event.get("catdesc"):
        result["event_category_desc"] = event.get("catdesc")

    if event.get("policyname"):
        result["policy_name"] = str(event.get("policyname"))

    if event.get("method"):
        result["network_request_method"] = event.get("ratemethod")

    if event.get("cat") is not None:
        result["event_category_id"] = str(event.get("cat"))

    if event.get("app"):
        result["applicationname"] = event.get("app")
        
    if event.get("sentbyte"):
        result["network_bytes_out"] = event.get("sentbyte")
        
    if event.get("rcvdbyte"):
        result["network_bytes_in"] = event.get("rcvdbyte")

    if event.get("hostname"):
        result["host_domain"] = event.get("hostname")
        
    if event.get("reason") or event.get("attack"):
        result["event_alert"] = str(event.get("reason") or event.get("attack"))

    if event.get("msg"):
        result["event_details"] = event.get("msg")

    if event.get("jumpserver"):
        result["jumpserver"] = event.get("jumpserver")

    return result



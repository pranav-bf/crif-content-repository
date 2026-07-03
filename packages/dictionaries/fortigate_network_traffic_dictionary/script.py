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
    if log == 'traffic' and dir != "outgoing":
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

    if event.get("action"):
        parts.append("Firewall action for traffic '%s'" % event.get("action"))
    else:
        parts.append("Firewall event")

    if event.get("srcip") or event.get("locip"):
        src_ip = event.get("srcip") or event.get("locip")
        parts.append("from source IP '%s'" % src_ip)

    if event.get("source_port") or event.get("srcport") or event.get("locport"):
        src_port = event.get("srcport") or event.get("locport")
        if src_port:
            parts.append("source port '%s'" % src_port)

    if event.get("dstip") or event.get("remip"):
        dst_ip = event.get("dstip") or event.get("remip")
        parts.append("to destination IP '%s'" % dst_ip)

    if event.get("destination_port") or event.get("dstport") or event.get("remport"):
        dst_port = event.get("dstport") or event.get("remport")
        if dst_port:
            parts.append("destination port '%s'" % dst_port)

    if event.get("devname") or event.get("ui"):
        parts.append("from device '%s'" % (event.get("devname") or event.get("ui")))

    if event.get("source_device_interface"):
        parts.append("on source interface '%s'" % event.get("source_device_interface"))

    if event.get("destination_device_interface"):
        parts.append("on destination interface '%s'" % event.get("destination_device_interface"))

    if event.get("destination_device_interface_role"):
        parts.append("with destination role '%s'" % event.get("destination_device_interface_role"))

    if event.get("network_protocol"):
        parts.append("using protocol '%s'" % event.get("network_protocol"))

    if event.get("destination_country"):
        parts.append("destination country '%s'" % event.get("destination_country"))

    if event.get("msg"):
        parts.append("details '%s'" % event.get("msg"))

    return " ".join(parts) + "."

def dictionary(event):
    result = {}

    if event.get("dstip") or event.get("remip"):
        result["destination_ip"] = str(event.get("dstip") or event.get("remip"))

    if event.get("srcport") or event.get("locport"):
        result["source_port"] = str(event.get("srcport") or event.get("locport"))

    if event.get("srcip") or event.get("locip"):
        result["source_ip"] = str(event.get("srcip") or event.get("locip"))

    if event.get("dstport") or event.get("remport"):
        result["destination_port"] = str(event.get("dstport") or event.get("remport"))

    if event.get("action"):
        result["event_action"] = event.get("action")

    if event.get("devname") or event.get("ui"):
        result["source_device_name"] = event.get("devname") or event.get("ui")

    if event.get("type"):
        result["log_type"] = event.get("type")

    if event.get("dstcountry"):
        result["destination_country"] = event.get("dstcountry")

    if event.get("dstintfrole"):
        result["destination_device_interface_role"] = str(event.get("dstintfrole"))

    if event.get("dstintf"):
        result["destination_device_interface"] = str(event.get("dstintf"))

    if event.get("srcintf"):
        result["source_device_interface"] = str(event.get("srcintf"))

    if event.get("service"):
        result["network_protocol"] = str(event.get("service"))

    if event.get("msg"):
        result["event_details"] = event.get("msg")

    if event.get("subtype"):
        result["log_subtype"] = event.get("subtype")

    if event.get("sentbyte"):
        result["network_bytes_out"] = event.get("sentbyte")

    if event.get("rcvdbyte"):
        result["network_bytes_in"] = event.get("rcvdbyte")
      
    if event.get("user"):
        result["user_name"] = str(event.get("user"))

    if event.get("app"):
        result["applicationname"] = event.get("app")
      
    if event.get("url"):
        result["url"] = event.get("url")

    if event.get("jumpserver"):
        result["jumpserver"] = event.get("jumpserver")

    return result



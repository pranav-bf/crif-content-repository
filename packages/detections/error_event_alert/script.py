def window():
    return None

def groupby():
    return ['source_country']

def algorithm(event):
    key = application.get("error_level")

    src_ip = event.get('source_ip')

    # incidrrange = cidr.inRange(src_ip, [
    #     "10.70.150.0/23",
    #     "10.70.151.0/24",
    #     "10.70.210.0/24",
    #     "10.70.220.0/23",
    #     "10.70.222.0/24"
    # ])

    # if incidrrange:
    #     return 0.0
      
    if key is True:
        return 0.0
      
    if event.get("event_level") == 3: #and event.get("event") in ['SSL', 'SSL VPN alert', 'SSL VPN exit error']:
        application.put("error_level", True, 86400)
        return 0.75

    return 0.0


def context(event_data):
    alert_name = event_data.get("event_alert")
    alert_type = event_data.get("log_subtype")
    alert=event_data.get("event")
    country=event_data.get("source_country")
    device = event_data.get("source_device_name")
    action = event_data.get("event_action")
    context ="Received error level event, "

    if action:
        context += "with action " + action
    if alert_type:
        context += " and alert type " + alert_type
    if alert:
        context += " indicating event of "+ alert
    if country:
        context += " from source country " + country
    if device:
        context += " for device " + device
    return context



def criticality():
    return "HIGH"

def tactic():
    return "Command and Control(TA0011)"


def technique():
    return "Application Layer Protocol (T1071)"



def artifacts():
    return stats.collect([
      "event_alert",
      "event_action",
      "source_country",
      "source_device_name",
    ])

def entity(event):
    return {"derived": False, "value": event.get("source_device_name") , "type": "device"}

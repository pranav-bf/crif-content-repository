def window():
    return '5m'

def groupby():
    return ['source_ip', 'source_device_name']

# def investigate():
#     return "fortigate_session_analyser"
  
# def automate():
#     return True

def algorithm(event):  
    action = event.get("event_action")
    src_ip = event.get('source_ip')
    key = application.get("suspicious_port")

    if key is True:
        return 0.0

    incidrrange = cidr.inRange(src_ip, [
        "10.70.150.0/23",
        "10.70.151.0/24",
        "10.70.210.0/24",
        "10.70.220.0/23",
        "10.70.222.0/24"
    ])

    if incidrrange:
        return 0.0
      
    if action!="deny":
        return 0.0
      
    dest_port = stats.accumulate(['destination_port'])
    unique_port=len(dest_port.get("destination_port"))
    if unique_port > 20:
      application.put("suspicious_port", True, 86400)
      stats.dissipate(['destination_port'])
      return 0.75
    return 0.0

def context(event_data):
    src_ip = event_data.get('source_ip')
    src_cnt = event_data.get('source_country')
    dst_cnt = event_data.get('destination_country')
    dst_ip = event_data.get('destination_ip')
    src_intf = event_data.get('source_device_interface')
    dst_intf = event_data.get('destination_device_interface')
    device = event_data.get('source_device_name')
    proto = event_data.get('network_protocol')
    dst_ports = event_data.get('destination_port')

    # Build the narrative
    message = (
        "The device {device} detected multiple denied connection attempts from {src_ip} ({src_cnt}) "
        "via interface {src_intf} targeting {dst_ip} ({dst_cnt}) on interface {dst_intf} "
        "using protocol {proto} across {dst_ports}. "
        "This activity is consistent with port scanning or network reconnaissance behavior, "
        "as the source host attempted connections to more than 20 ports within a 5 minutes timeframe."
    ).format(
        device=device,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_intf=src_intf,
        dst_intf=dst_intf,
        proto=proto,
        dst_ports=dst_ports,
        src_cnt=src_cnt,
        dst_cnt=dst_cnt
    )

    return message

def criticality():
    return 'HIGH'

def tactic():
    return 'Reconnaissance (TA0043)'

def technique():
    return 'Active Scanning (T1595)'

def artifacts():
    return stats.collect(['destination_port', 'source_ip','destination_ip', 'network_protocol', 'source_country', 'destination_country'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
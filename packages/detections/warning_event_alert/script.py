def window():
    return None


def groupby():
    return ['source_ip']

def algorithm(event):
    key = application.get("event_level_warning")
    
    if key is True:
        return 0.0
      
    destination_ip = event.get("destination_ip")
    # dnsservers = []

    if event.get("event_level") == 4:
      application.put("event_level_warning", True, 86400)
      return 0.50

    return 0.0
                

def context(event):
    source_hw_vendor = event.get("source_hw_vendor")
    source_hw_version = event.get("source_hw_version")
    source_family = event.get("source_family")
    source_name = event.get("source_name")
    source_device_interface = event.get("source_device_interface")
    event_action = event.get("event_action")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")
    policy_name = event.get("policy_name")
    event_duration = event.get("event_duration")
    network_bytes_in = event.get("network_bytes_in")
    # vpn=event.get("details").get("vpn")
    # vpntype=event.get("details").get("vpntype")
    source_device_name=event.get("source_device_name")
    network_packets_in=event.get("network_packets_in")
    network_packets_out=event.get("network_packets_out")
    source_mac_address=event.get("source_mac_address")
    alert_score=event.get("alert_score")
    os_name=event.get("os_name")
    
    source_ip = event.get("source_ip")
    protocol=event.get("details").get("proto")
    applicationname=event.get("applicationname")


    context = "A Fortigate firewall flagged a warning-level event involving "

    if os_name:
        context += "an OS named " + os_name + " "
    if source_hw_vendor:
        context += "running on a " + source_hw_vendor + " "
    if source_hw_version:
        context += source_hw_version + " "
    if source_family and source_name:
        context += source_family + " device, specifically the " + source_name + ". "
    if source_device_interface:
        context += "The event was detected on the " + source_device_interface + " interface and involved a "
    if event_action:
        context += event_action + " action directed towards the IP address "
    if destination_ip:
        context += destination_ip + " "
    if protocol:
        context += "using the " + protocol + " protocol "
    if destination_port:
        context += "on port " + destination_port + ". "
    if applicationname:
        context += "This action was initiated by the " + applicationname + " application. "
    if policy_name:
        context += "The session, governed by the '" + policy_name + "' policy, "
    if event_duration:
        context += "lasted for " + event_duration + " seconds and "
    if network_bytes_in:
        context += "exchanged " + network_bytes_in + " bytes. "
    # if vpntype or vpn:
    #     context += "It was part of the "
    #     if vpntype:
    #         context += vpntype + " VPN "
    #     if vpn:
    #         context += "identified as " + vpn + ". "
    if source_device_name:
        context += "The device, named " + source_device_name + ", "
    if network_packets_in:
        context += "recorded " + network_packets_in + " packets sent and "
    if network_packets_out:
        context += network_packets_out + " packets received. "
    if source_ip:
        context += "The source IP was " + source_ip + " "
    if source_mac_address:
        context += "with a MAC address of " + source_mac_address + ". "
    if alert_score:
        context += "This event requires further scrutiny due to its criticality score of " + str(alert_score) + "."

    return context


def criticality():
    count = stats.getcount("event_level_warning")
    if count == 30:
        return "MEDIUM"


def tactic():
    return "Command and Control (TA0011)"


def technique():
    return "Application Layer Protocol (T1071)"


def artifacts():
    try:
        return stats.collect(["event_level", "source_ip", "destination_ip"])
    except Exception as e:
        raise e


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
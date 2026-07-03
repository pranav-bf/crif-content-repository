def window():
    return None


def groupby():
    return None

def algorithm(event):
    destination_ip = event.get("destination_ip")
    dnsservers = ['10.10.102.52','10.10.2.52']
    if event.get("event_level") == 2 and destination_ip not in dnsservers:
        return 1.0

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
    destination_ip = event.get("destination_ip")
    vpn=event.get("details").get("vpn")
    vpntype=event.get("details").get("vpntype")
    source_device_name=event.get("source_device_name")
    network_packets_in=event.get("network_packets_in")
    network_packets_out=event.get("network_packets_out")
    source_mac_address=event.get("source_mac_address")
    alert_score=event.get("alert_score")
    os_name=event.get("os_name")
    
    source_ip = event.get("source_ip")
    protocol=event.get("details").get("proto")
    applicationname=event.get("applicationname")
    context = "A Fortigate firewall flagged a critical-level event involving "

    if os_name:
        context += "an OS named " + os_name + " "
    if source_hw_vendor:
        context += "running on hardware from " + source_hw_vendor + " "
    if source_hw_version:
        context += "with version " + source_hw_version + " "
    if source_family:
        context += "belonging to the " + source_family + " family, "
    if source_name:
        context += "specifically the " + source_name + " model. "
    if source_device_interface:
        context += "The event was detected on the " + source_device_interface + " interface, which initiated a "
    if event_action:
        context += event_action + " action to "
    if destination_ip:
        context += destination_ip + " using "
    if protocol:
        context += protocol + " protocol on port "
    if destination_port:
        context += destination_port + ". "
    if applicationname:
        context += "This was initiated by the " + applicationname + " application. "
    if policy_name:
        context += "The session was governed by the '" + policy_name + "' policy, "
    if event_duration:
        context += "lasted for " + str(event_duration) + " seconds, "
    if network_bytes_in:
        context += "and exchanged " + str(network_bytes_in) + " bytes. "
    if vpntype or vpn:
        context += "It was part of a "
        if vpntype:
            context += vpntype + " VPN "
        if vpn:
            context += "identified as " + vpn + ". "
    if source_device_name:
        context += "The device, identified as " + source_device_name + ", "
    if network_packets_in:
        context += "logged " + str(network_packets_in) + " packets sent and "
    if network_packets_out:
        context += str(network_packets_out) + " packets received. "
    if source_ip:
        context += "The source IP was " + source_ip + " "
    if source_mac_address:
        context += "with a MAC address of " + source_mac_address + ". "
    if alert_score:
        context += "This event requires further scrutiny due to its criticality score of " + str(alert_score) + "."

    return context

def criticality():

    return "CRITICAL"


def tactic():
    return "Command and Control(TA0011)"


def technique():
    return "Application Layer Protocol (T1071)"


def artifacts():
    try:
        return stats.collect(["event_level", "source_ip"])
    except Exception as e:
        raise e


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
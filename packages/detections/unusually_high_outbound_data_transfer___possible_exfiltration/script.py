import traceback
def init(event):
    try:
        analysis = stats.zanomaly('network_bytes_transferred')
        session.set("anomalies", [analysis])
        return "Initialized zanomaly detection"
    except Exception as e:
        print ("Error in init:"+ str(e))
        traceback.print_exc()
        session.set("anomalies", [])
        return "Initialization failed"


def window():
    return '15m'

def groupby():
    return ['source_ip', 'destination_ip']

def investigate():
    return "fortigate_session_analyser"

def automate():
    return False

def algorithm(event):
    analysis = session.get("anomalies")[0]
    print("analysis : "+str(analysis))
    anomaly = analysis.get("anomaly")
    print("anomaly : "+str(anomaly))
    if anomaly == 1 :
      return 0.75 


  
def clusters(event):
    try:
        cluster = session.get("anomalies")[0]
        cluster["unit"] = "bytes"
        return [cluster]
    except Exception as e:
        print ("Error in clusters:"+ str(e))
        traceback.print_exc() 
        return []



def context(event_data):
    analysis = session.get("anomalies")[0]
    mean = analysis.get('mean')
    # Safely extract relevant FortiGate log values with defaults
    src_ip = event_data.get('source_ip')
    dst_ip = event_data.get('destination_ip')
    src_intf = event_data.get('source_device_interface')
    dst_port = event_data.get('destination_port')
    device = event_data.get('source_device_name')
    proto = event_data.get('network_protocol')

    # Build the narrative
    message = (
        "The device {device} was observed sending unusually high volume of outbound traffic "
        "from {src_ip} via interface {src_intf} targeting {dst_ip} on port {dst_port} "
        "using protocol {proto}."
        "Mean of bytes transmitted in a 15 minutes duration is {mean}, "
        "which may indicate potential data exfiltration, unauthorized file transfer, "
        "or covert tunneling activity."
    ).format(
        device=device,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_intf=src_intf,
        dst_intf=dst_port,
        proto=proto,
        mean=mean
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration Over Web Services (T1567)'

def artifacts():
    return stats.collect(['event_action', 'network_bytes_transferred', 'source_ip', 'destination_ip', 'network_protocol'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
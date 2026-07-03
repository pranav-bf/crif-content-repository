
  
def format():
  return "statcardwithicon"


def query():
    return {
        'query': 'select distinct on (source_device_name) last_log,total_events,source_device_name from device_event_edge where source_device_name is not null and partition_key = :partition_key order by source_device_name, total_events desc',
        'parameters': {"partition_key":"Fortinet~FortiGate~Firewall"}
    }


def render(result):
    
    total = 0

    if result and len(result) > 0:
        # Query already returns distinct hosts
        total = len([
            row for row in result
            if row.get("source_device_name") and ":" not in row.get("source_device_name", "")
        ])
    
    return {
        "result": {
            "labels": ["Fortigate Device"],
            "data": [
                {
                    "label": "Fortigate Device",
                    "data": [total],
                    "icon": ["devices"],
                    "iconClass": ["icon-orange"]
                }
            ]
        }
    }


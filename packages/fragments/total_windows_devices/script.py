
  
def format():
  return "statcardwithicon"


def query():
  return {
      'query': 'select distinct on (host) last_log,total_events,host from device_event_core where host is not null and partition_key = :partition_key order by host, total_events desc',
      'parameters': {"partition_key":"Microsoft~Windows~Audit"}
  }


def render(result):
    
    total = 0

    if result and len(result) > 0:
        # Query already returns distinct hosts
        total = len([
            row for row in result
            if row.get("host") and ":" not in row.get("host", "")
        ])
    
    return {
        "result": {
            "labels": ["Windows Device"],
            "data": [
                {
                    "label": "Windows Device",
                    "data": [total],
                    "icon": ["window"],
                    "iconClass": ["icon-indigo"]
                }
            ]
        }
    }


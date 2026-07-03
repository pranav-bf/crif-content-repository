# Format: Statcard
def format():
    return "statcard"
  
def query():
    
    return {
        "query": "SELECT sum(detection_count) FROM detection_count_all_time",
        "parameters": {}
    }

def render(results):
    total = 0

    if results and len(results) > 0:
        total = results[0].get("sum(detection_count)", 0)

    print(total)
    # Ensure it's numeric
    total = int(total)
    print(total)
    # Format with thousands separator
    total = "{:,}".format(total)
    print(total)

    return {
        "result": {
            "labels": ["Total Detections"],
            "data": [
                {
                    "label": "Detections",
                    "data": [total]
                }
            ]
        }
    }

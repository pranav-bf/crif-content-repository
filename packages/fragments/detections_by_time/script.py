# Format: Statcard
def format():
    return "statcard"

def query():
    
    return {
        "query": "select  sum(total_count) as detection_count from detection_trends_daily",
        "parameters": {}
    }

def render(results):
    print(results)

    total = 0
    if results and len(results) > 0:
        total = results[0].get("detection_count", 0)
    
    # Ensure it's numeric
    total = int(total)

    # Format with thousands separator
    total = "{:,}".format(total)

    return {
        "result": {
            "labels": ["Detections (Last six months)"],
            "data": [
                {
                    "label": "Detections",
                    "data": [total]
                }
            ]
        }
    }


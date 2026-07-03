# Format: Statcard
def format():
    return "statcard"

def query():
    
    return {
        "query": "select count(id) as total_incidents from incidentdetails",
        "parameters": {}
    }
def render(results):
    print(results)

    total = 0
    if results and len(results) > 0:
        total = results[0].get("total_incidents", 0)
    
    # Ensure it's numeric
    total = int(total)

    # Format with thousands separator
    total = "{:,}".format(total)


    return {
        "result": {
            "labels": ["Incidents resolved (Last six months) "],
            "data": [
                {
                    "label": "Resolved",
                    "data": [total]
                }
            ]
        }
    }

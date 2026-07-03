# Format: Specifies the format for the data.

def format():
    return "stackedBar"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select provider, COUNT(*) AS total_events FROM aggregation_table WHERE provider IS NOT NULL AND type =:type GROUP BY provider",
        "parameters": {"type": "tenant_health_monitor_breakdown"}
    }


def render(results):
    if not results:
        raise Exception("no results found")

    labels = []
    total_events = []

    for r in results:
        labels.append(r["provider"])
        log_value =  r["total_events"]
        total_events.append(log_value)
    data=[
        {
            "label": "Events",
            "data": total_events,
            "backgroundColor": "#2ecc71"
        }
    ]

    return {"result": {"labels": labels, "data": data}}

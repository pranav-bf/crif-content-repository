# Format: Statcard
def format():
    return "statcard"


# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select count(status) as total_closed from incidentdetails where status != :type and criticality = :severity",
        "parameters": {"type":"closed", "severity":"HIGH"}
    }

def render(results):

    total = 0
    if results and len(results) > 0:
        total = results[0].get("total_closed", 0)

    # Ensure it's numeric
    total = int(total)

    # Format with thousands separator
    total = "{:,}".format(total)

    return {
        "result": {
            "labels": ["Open Cases (High)"],
            "data": [
                {
                    "label": "Cases",
                    "data": [total]
                }
            ]
        }
    }
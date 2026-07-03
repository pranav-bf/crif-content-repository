# Format: Statcard
def format():
    return "statcard"


# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select count(id) as total_cases from incidentdetails",
        "parameters": {}
    }

def render(results):

    total = 0
    if results and len(results) > 0:
        total = results[0].get("total_cases", 0)

    # Ensure it's numeric
    total = int(total)

    # Format with thousands separator
    total = "{:,}".format(total)

    return {
        "result": {
            "labels": ["Total Cases"],
            "data": [
                {
                    "label": "Cases",
                    "data": [total]
                }
            ]
        }
    }
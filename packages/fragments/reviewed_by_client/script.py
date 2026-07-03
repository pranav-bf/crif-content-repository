def format():
    return "statcard"

def query():
    return {
        "query": "SELECT  COUNT(*) AS count FROM incidenthistory WHERE status = :stat",
        "parameters": {"stat" :"Reviewed by client"}
    }

def render(results):

    total = 0

    if results and len(results) > 0:
        # Handle both dict styles: {'count': 0} or {'count': '0'}
        total = int(results[0].get("count", 0))
    
    # Ensure it's numeric
    total = int(total)

    # Format with thousands separator
    total = "{:,}".format(total)

    return {
        "result": {
            "labels": ["Client Reviewed (six months) "],
            "data": [
                {
                    "label": "Events",
                    "data": [total]
                }
            ]
        }
    }

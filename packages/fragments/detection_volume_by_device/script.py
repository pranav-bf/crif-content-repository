def format():
    return "tabular"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "SELECT host, streamprovider, COUNT(*) AS totaldetection FROM detection WHERE host IS NOT NULL AND streamprovider IS NOT NULL GROUP BY host, streamprovider ORDER BY totaldetection DESC "
    }

def render(results):
    if not results or len(results) == 0:
        raise Exception("no results found")

    # Assuming each row has consistent keys: 'provider', 'host', 'total'
    labels = ["Provider", "Device", "Total Detections"]
    data = []

    for row in results:
        provider = row.get("streamprovider", "")
        host = row.get("host", "")
        total = row.get("totaldetection", 0)
        data.append([provider, host, total])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
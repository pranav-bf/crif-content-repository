# Format: Specifies the format for the data.



def format():
    return "tabular"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "SELECT provider, host ,count(*) as total FROM aggregation_table WHERE  provider IS NOT NULL AND host IS NOT NULL and type= :type group by provider,host order by total desc",
        "parameters": {"type":"tenant_health_monitor_breakdown"}
    }

def render(results):
    if not results or len(results) == 0:
        raise Exception("no results found")

    # Assuming each row has consistent keys: 'provider', 'host', 'total'
    labels = ["Provider", "Device", "Total Events"]
    data = []

    for row in results:
        provider = row.get("provider", "")
        host = row.get("host", "")
        total = row.get("total", 0)
        data.append([provider, host, total])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }

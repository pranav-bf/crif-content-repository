def format():
    return "tabular"

def query():
    
    return {
        "query": "SELECT devicename, sum(total_count) AS totaldetection FROM hostnames_daily_summary WHERE devicename IS NOT NULL GROUP BY devicename ORDER BY totaldetection DESC ",
        "parameters":{},
        "options": { "limit": 10}
    }
  
def render(results):
  
    if not results or len(results) == 0:
        raise Exception("no results found")

    labels = ["Device", "Total Detections"]
    data = []

    for row in results:
        device = row.get("devicename")
        total = row.get("totaldetection", 0)

        formatted_total = "{:,}".format(total)

        data.append([device, total])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }

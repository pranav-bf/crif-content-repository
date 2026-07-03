def format():
    return "tabular"

def query():
    return [{
        "query": "select detectionid,count(*) as total from detection_trends_daily group by detectionid order by total",
        "parameters": {}
    },
            
    {
        "query": """SELECT DISTINCT ON (detectionid)
    detectionid,
    detectionname
FROM attackpath
ORDER BY detectionid, createdon DESC""",
        "parameters": {}
    }]

def render(results):
    print(results)

    labels = ["DETECTION TITLE", "COUNT"]
    data = []

    if not results or len(results) < 2:
        return {
            "result": {
                "labels": labels,
                "data": []
            }
        }

    counts_list = results[0]   # detectionid + total
    names_list = results[1]    # detectionid + detectionname

    # Step 1: Build detectionid → detectionname map
    id_to_name = {}
    for row in names_list:
        id_to_name[row.get("detectionid")] = row.get("detectionname")

    # Step 2: Merge totals with names
    merged_data = []
    for row in counts_list:
        detection_id = row.get("detectionid")
        total = row.get("total", 0)

        detection_name = id_to_name.get(detection_id)

        merged_data.append({
            "detectionname": detection_name,
            "total": total
        })

    # Step 4: Prepare final data (top 10)
    for row in merged_data[:10]:
        data.append([
            row.get("detectionname"),
            row.get("total", 0)
        ])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }

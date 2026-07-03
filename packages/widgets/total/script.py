def configure():
    return {
        "searchable": False,
        "properties": {
            "type": "statcard",
            "layout": "card",
            "graphtype": "trend"
        },
        "dimension": {"x": 0, "y": 0, "width": 3, "height": 1}
    }

def query():
    return {
        "query": """
            SELECT name, COUNT(*) AS count
            FROM detection 
            WHERE name IS NOT NULL
            GROUP BY name;
        """,
        "parameters": {}
    }



def render(results):
    categories = []
    data = []
    total = 0

    for row in results:
        label = row["name"]
        count = row["count"]
        categories.append(label)
        data.append(count)
        total += count

    series = [{
        "name": "TOTAL DETECTIONS",
        "data": data
    }]

    return {
        "result": {
            "categories": categories,
            "series": series,
            "total": total,
            "className":"dlp-dashboardstats"
        }
    }

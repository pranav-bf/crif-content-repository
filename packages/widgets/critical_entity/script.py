def configure():
    return {
        "searchable": False,
        "properties": {
            "type": "statcard",
            "layout": "card",
            "graphtype": "trend"
        },
        "dimension": {"x": 6, "y": 0, "width": 3, "height": 1}
    }

def query():
    return {
        "query": """
            SELECT
                entity,
                COUNT(*) AS count
            FROM
                detection
            WHERE
                criticality = 'CRITICAL'
            GROUP BY
                entity
            ORDER BY count DESC;
        """,
        "parameters": {}
    }


def render(results):
    categories = []
    data = []
    total = 0

    for row in results:
        label = row["entity"]
        count = row["count"]
        categories.append(label)
        data.append(count)
        total += count
      
    if total == 0:
        categories = ["No Critical"]
        data = [0]

    series = [{
        "name": "Critical Entity",
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

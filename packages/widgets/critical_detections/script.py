def configure():
    return {
        "searchable": False,
        "properties": {
            "type": "statcard",
            "layout": "card",
            "graphtype": "bar"
        },
        "dimension": {"x": 3, "y": 0, "width": 3, "height": 1}
    }

def query():
    return {
        "query": """
            SELECT
                detectioncriticality,
                COUNT(*) AS count
            FROM
                entityscoring
            WHERE
                detectioncriticality = 'CRITICAL'
            GROUP BY
                detectioncriticality
            ORDER BY count DESC;
        """,
        "parameters": {}
    }

def filters(filters):
    return None

def search(freetext):
    return None

def sort():
    return None

def render(results):
    categories = []
    data = []
    total = 0

    for row in results:
        label = row["detectioncriticality"]
        count = row["count"]
        categories.append(label)
        data.append(count)
        total += count

    if total == 0:
        categories = ["CRITICAL"]
        data = [0]

    series = [{
        "name": "CRITICAL DETECTIONS",
        "data": data
    }]

    return {
        "result": {
            "categories": categories,
            "series": series,
            "total": total
        }
    }

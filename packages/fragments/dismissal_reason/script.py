# Format: Specifies the format for the data (doughnut)
def format():
    return "polarArea"


# Query: Retrieves counts of detections by dismissal reason.
def query():
    return {
        "query": "SELECT status, COUNT(*) AS count FROM incidenthistory WHERE status IN (:stat) GROUP BY status ORDER BY count DESC",
        "parameters": {"stat" :['False Positive','No action required','Rule defective','Informational event','Benign activity']}
    }

def render(results):

    labels = [
        "False Positive",
        "No action required",
        "Rule defective",
        "Informational event",
        "Benign activity"
    ]

    color_map = {
        "False Positive": "#3B82F6",
        "No action required": "#10B981",
        "Rule defective": "#F59E0B",
        "Informational event": "#EF4444",
        "Benign activity": "#6366F1"
    }

    # Initialize all counts to 0
    counts_map = {}
    for label in labels:
        counts_map[label] = 0

    # Fill counts from query results
    if results:
        for row in results:
            status = row.get("status")
            count = row.get("count", 0)

            if status in counts_map:
                counts_map[status] = count

    # Maintain label order
    data_points = []
    for l in labels:
        data_points.append(counts_map[l])

    colors = []
    for l in labels:
        colors.append(color_map[l])

    dataset = [{
        "data": data_points,
        "backgroundColor": colors,
        "borderWidth": 1
    }]

    options = {
        "responsive": True,
        "maintainAspectRatio": False,
        "plugins": {
            "legend": {
                "display": True,
                "position": "top",
                "align": "center",
                "labels": {
                    "boxWidth": 10,
                    "boxHeight": 10,
                    "padding": 12,
                    "usePointStyle": True,
                    "pointStyle": "circle",
                    "font": {
                        "size": 11
                    }
                }
            }
        }
    }

    return {
        "result": {
            "labels": labels,
            "data": dataset,
            "options": options
        }
    }
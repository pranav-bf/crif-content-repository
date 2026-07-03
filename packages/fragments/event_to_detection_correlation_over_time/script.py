from datetime import datetime


def format():
    return "line"


def query():
    return [
        {
            "query": """
                SELECT date_trunc('month', insert_date) AS event_month,
                       SUM(statcount) AS total_events
                FROM streamx
                WHERE objectid IN (:streamids)
                  AND stattype = :statype
                GROUP BY event_month
                ORDER BY event_month ASC
            """,
            "parameters": {
                "streamids": [
                    "69cead239bf814670aefac6d",
                    "69cc26c66c71ad11f75ae966",
                    "69d0faf59bf814670aefad46"
                ],
                "statype": "PUBLISHED"
            }
        },
        {
            "query": """
                SELECT date_trunc('month', insert_date) AS event_month,
                       SUM(statcount) AS total_detections
                FROM streamx
                WHERE stattype = :statype
                GROUP BY event_month
                ORDER BY event_month ASC
            """,
            "parameters": {
                "statype": "DETECTIONS"
            }
        }
    ]


def render(results):
    print(results)

    if not results or len(results) < 2:
        return {"result": {"labels": [], "data": []}}

    labels = []
    event_counts = []
    detection_counts = []

    # EVENTS (results[0])
    for row in results[0]:
        event_month = row.get("event_month")
        total_events = row.get("total_events", 0)

        dt = datetime.strptime(event_month[:19], "%Y-%m-%dT%H:%M:%S")
        labels.append(dt.strftime("%b %Y"))
        event_counts.append(total_events)

    # DETECTIONS (results[1])
    for row in results[1]:
        total_detections = row.get("total_detections", 0)
        detection_counts.append(total_detections)

    dataset = [
        {
            "label": "Events",
            "data": event_counts,
            "borderColor": "#10B981",
            "backgroundColor": "rgba(16, 185, 129, 0.15)",
            "tension": 0.4,
            "fill": True,
            "yAxisID": "y_events"
        },
        {
            "label": "Detections",
            "data": detection_counts,
            "borderColor": "#3B82F6",
            "backgroundColor": "rgba(59, 130, 246, 0.15)",
            "tension": 0.4,
            "fill": True,
            "yAxisID": "y_detections"
        }
    ]

    options = {
        "scales": {
            "y_events": {
                "type": "linear",
                "position": "left",
                "beginAtZero": True,
                "ticks": {"color": "#10B981"},
                "title": {
                    "display": True,
                    "text": "Total Events",
                    "color": "#10B981"
                },
                "grid": {"color": "rgba(16,185,129,0.1)"}
            },
            "y_detections": {
                "type": "linear",
                "position": "right",
                "beginAtZero": True,
                "ticks": {"color": "#3B82F6"},
                "title": {
                    "display": True,
                    "text": "Total Detections",
                    "color": "#3B82F6"
                },
                "grid": {"drawOnChartArea": False}
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
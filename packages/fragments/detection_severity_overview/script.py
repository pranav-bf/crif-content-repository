def format():
    return "doughnut"

def query():
    return {"query": "Select distinct detectioncriticality , count(*) as totalevents from detection_severity_trends_hourly WHERE detectioncriticality != :criticality and  detectioncriticality is not null  group by detectioncriticality",
  "parameters": {"criticality":"NONE"} }

def render(results):
    print(results)

    color_map = {
        "CRITICAL": "#9B2C2C",
        "HIGH": "#8A5A2B",
        "MEDIUM": "#EAA03B",
        "LOW": "#E5E7EB"
    }

    labels = []
    data_points = []
    colors = []

    if results:
        for row in results:
            crit = row.get("detectioncriticality")
            count = row.get("totalevents", 0)
            labels.append(crit)
            data_points.append(count)
            colors.append(color_map.get(crit, "#CBD5E1"))

    # --- Append percentage to each label ---
    total_all = sum(data_points) or 1
    labels = [
        "%s (%.1f%%)" % (lbl, (data_points[i] / float(total_all)) * 100)
        for i, lbl in enumerate(labels)
    ]

    dataset = [{"data": data_points, "backgroundColor": colors}]

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
                    "font": {"size": 11}
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

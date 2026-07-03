# Format: Specifies the format for the data.
def format():
    return "doughnut"

# Query: Specifies the query to retrieve data.
def query():
    return {"query": "select tactic, count (tactic) as tactic_count from detection_trends_daily group by tactic;",
    "parameters": {}
  }

def render(results):
    print(results)
    TOP_N = 5
    color_map = {
        "Initial Access": "#1E3A8A",
        "Execution": "#1D4ED8",
        "Persistence": "#3B82F6",
        "Privilege Escalation": "#2563EB",
        "Credential Access": "#1E40AF",
        "Command and Control": "#60A5FA",
        "Discovery": "#93C5FD",
        "Lateral Movement": "#1E429F",
        "Collection": "#1E3A8A",
        "Exfiltration": "#172554",
        "Impact": "#0F172A",
        "Others": "#E5E7EB"
    }
    tactic_counts = {}
    if results:
        for row in results:
            raw_tactic = row.get("tactic", "")
            count = row.get("tactic_count", 0)
            tactic = raw_tactic.split("(")[0].strip()
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + count
    sorted_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
    labels = []
    data_points = []
    colors = []
    others_total = 0
    for index, (tactic, count) in enumerate(sorted_tactics):
        if index < TOP_N:
            labels.append(tactic)
            data_points.append(count)
            colors.append(color_map.get(tactic, "#CBD5E1"))
        else:
            others_total += count
    if others_total > 0:
        labels.append("Others")
        data_points.append(others_total)
        colors.append(color_map["Others"])
    # ---- Append percentage to each label ----
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
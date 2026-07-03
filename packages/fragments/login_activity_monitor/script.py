# Format: Specifies the format for the data.
from datetime import datetime

def format():
    return "line"
  

# Query: Specifies the query to retrieve data.
def query():

    return [{
        "query": """select hour_window,sum(successful_logins) AS total_events  FROM windows_privileged_hourly_activity
            WHERE source_account_name IN (
                SELECT DISTINCT source_account_name
                FROM windows_privileged_hourly_activity
                WHERE privilege_escalations > 0
            ) group by hour_window ,successful_logins order by hour_window asc""",
        "parameters": {}
    },{
        "query": """select hour_window,sum(failed_logins) AS total_events  FROM windows_privileged_hourly_activity
            WHERE source_account_name IN (
                SELECT DISTINCT source_account_name
                FROM windows_privileged_hourly_activity
                WHERE privilege_escalations > 0
            ) group by hour_window  order by hour_window asc""",
        "parameters": {}
    }]


from datetime import datetime

def render(results=None):

    successful = results[0] or []
    total = results[1] or []

    def ms(v):
        try:
            return datetime.fromtimestamp(int(v)/1000).strftime("%d %b %H:%M")
        except:
            return str(v)

    # aggregate safely (because SQL returns duplicates)
    total_map = {}
    priv_map = {}

    for r in successful:
        hour = ms(r["hour_window"])
        priv_map[hour] = priv_map.get(hour, 0) + int(r["total_events"])

    for r in total:
        hour = ms(r["hour_window"])
        total_map[hour] = total_map.get(hour, 0) + int(r["total_events"])

    labels = sorted(set(total_map.keys()) | set(priv_map.keys()))

    datasets = [
        {
            "label": "PRIVILEGED FAILED LOGIN",
            "data": [total_map.get(l,0) for l in labels],
            "borderColor": "#EF4444",
            "backgroundColor": "rgba(239,68,68,0.15)",
            "fill": True,
            "tension": 0.3,
            "yAxisID": "y_total"
        },
        {
            "label": "PRIVILEGED SUCCESSFUL LOGIN",
            "data": [priv_map.get(l,0) for l in labels],
            "borderColor": "#10B981",
            "backgroundColor": "rgba(16,185,129,0.15)",
            "fill": True,
            "tension": 0.3,
            "yAxisID": "y_priv"
        }
    ]

    options = {
    "scales": {
        "y_total": {
            "type": "linear",
            "position": "left",
            "beginAtZero": True,
            "ticks": {
                "color": "#EF4444"
            },
            "title": {
                "display": True,
                "text": "Privileged Failed Logins",
                "color": "#EF4444"
            },
            "grid": {
                "color": "rgba(239,68,68,0.15)"
            }
        },
        "y_priv": {
            "type": "linear",
            "position": "right",
            "beginAtZero": True,
            "ticks": {
                "color": "#10B981"
            },
            "title": {
                "display": True,
                "text": "Privileged Successful Logins",
                "color": "#10B981"
            },
            "grid": {
                "drawOnChartArea": False
            }
        }
    }
}

    return {
        "result":{
            "labels": labels,
            "data": datasets,
            "options": options
        }
    }
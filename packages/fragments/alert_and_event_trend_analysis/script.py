
# Format: Specifies the format for the data.
from datetime import datetime

def format():
    return "line"

# Query: Specifies the query to retrieve data.
def query():

    return [{
        "query": "select minute_window,total_count AS total_events FROM streamx_trends_minute where stattype= :stattype ORDER BY  minute_window ASC",
        "parameters": {"stattype":"PUBLISHED"}
    },{
        "query": "select minute_window,total_count AS total_events FROM streamx_trends_minute where stattype= :stattype ORDER BY  minute_window ASC",
        "parameters": {"stattype":"DETECTIONS"}
    }]





def render(results=None):

    events_result = results[0]
    detections_result = results[1]

    normalized = []

    # Step 1 - Normalize raw results
    for row in events_result:
        normalized.append({
            "time": row["minute_window"],
            "total_count": row["total_events"],
            "type": "EVENTS"
        })

    for row in detections_result:
        normalized.append({
            "time": row["minute_window"],
            "total_count": row["total_events"],
            "type": "DETECTIONS"
        })

    # ----------------------------------------------------
    # STEP 2 – FIRST LEVEL AGGREGATION → HOURLY
    # ----------------------------------------------------

    hourly_grouped = {}

    def hour_bucket(ts):
      clean = ts.replace("T", " ")
      return clean[:13]

    for row in normalized:
        t = row["type"]
        hb = hour_bucket(row["time"])

        if t not in hourly_grouped:
            hourly_grouped[t] = {}

        if hb not in hourly_grouped[t]:
            hourly_grouped[t][hb] = 0

        hourly_grouped[t][hb] += row["total_count"]

    # All unique hours after first aggregation
    all_hours = sorted(
        list({hour_bucket(row["time"]) for row in normalized})
    )

    # ----------------------------------------------------
    # STEP 3 – DECIDE IF NEED DAILY AGGREGATION
    # ----------------------------------------------------

    if len(all_hours) <= 26:

        # ---- FINAL DATA IS HOURLY ----
        final_grouped = hourly_grouped
        final_labels = all_hours

    else:

        # ---- SECOND LEVEL AGGREGATION → DAILY ----

        daily_grouped = {}

        def day_bucket(ts):
          return ts.replace("T", " ")[:10]


        for t, hour_map in hourly_grouped.items():

            if t not in daily_grouped:
                daily_grouped[t] = {}

            for hour, count in hour_map.items():
                db = day_bucket(hour)

                if db not in daily_grouped[t]:
                    daily_grouped[t][db] = 0

                daily_grouped[t][db] += count

        final_grouped = daily_grouped
        final_labels = sorted(
            list({day_bucket(h) for h in all_hours})
        )

    # ----------------------------------------------------
    # STEP 4 – PREPARE CHART DATASETS
    # ----------------------------------------------------

    color_map = {
        "EVENTS": "#3498db",
        "DETECTIONS": "#e74c3c",
    }

    data = []

    for event_type, time_map in final_grouped.items():
        data.append({
            "label": event_type,
            "data": [time_map.get(label, 0) for label in final_labels],
            "borderColor": color_map.get(event_type, "#95a5a6"),
            "fill": False,
            "tension": 0.3
        })

    return {
        "result": {
            "labels": final_labels,
            "data": data
        }
    }

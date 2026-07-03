import datetime

# ===============================
# Fragment format
# ===============================
def format():
    return "bar"


# ===============================
# Query
# ===============================
def query():
    return {
        "query": """
                    SELECT
            EXTRACT(HOUR FROM to_timestamp(hour_bucket_ms / 1000)) AS hour_of_day,
            detectioncriticality,
            SUM(detection_count) AS total_detections
        FROM detection_severity_trends_hourly
        where detectioncriticality != :criticalitytype
        GROUP BY hour_of_day, detectioncriticality
        ORDER BY hour_of_day ASC;
        """,
        "parameters": {"criticalitytype": "NONE"}
    }


# ===============================
# Render
# ===============================
def render(results):
    print(results)
    labels = ["%02d:00" % h for h in range(24)]

    # Only 3 severity levels now
    severity_buckets = {
        "CRITICAL": [0] * 24,
        "HIGH":     [0] * 24,
        "MEDIUM":   [0] * 24
    }

    if results:
        for row in results:
            hour = row.get("hour_of_day")
            ts_ms = row.get("timestampbyhour")

            if ts_ms is not None:
                dt = datetime.datetime.fromtimestamp(ts_ms / 1000.0)
                hour = dt.hour

            severity = row.get("detectioncriticality")

            # Your query returns total_detections
            count = row.get("total_detections") or 0

            if hour is None or severity not in severity_buckets:
                continue

            severity_buckets[severity][int(hour)] = count

    # Professional severity colors
    severity_fill = {
        "CRITICAL": "#7F1D1D",  # Dark Red
        "HIGH":     "#DC2626",  # Red
        "MEDIUM":   "#F59E0B"   # Amber
    }

    data = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        data.append({
            "label": severity,
            "data": severity_buckets[severity],
            "backgroundColor": severity_fill[severity],
            "borderColor": severity_fill[severity],
            "borderWidth": 1,
            "categoryPercentage": 0.8,
            "barPercentage": 0.9
        })

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }

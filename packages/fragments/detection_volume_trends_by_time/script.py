from datetime import datetime
from collections import defaultdict

# Format: Specifies the format for the data.
def format():
    return "line"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select detectiontime ,COUNT(*) AS hourly_count from detection group by detectiontime order by detectiontime ASC",
        "parameters": {}
    }


def render(results):
   
    # Build detection buckets if any data exists
    if not results or len(results) == 0:
        raise Exception("No time buckets found in query")

    # Step 1: Create buckets for detectiontime
    detection_buckets = defaultdict(int)
 
    for row in results:
        ts = row.get('detectiontime')
        if ts is not None:
            dt = datetime.utcfromtimestamp(ts / 1000)
            dt_truncated = dt.replace(minute=0, second=0, microsecond=0)
            detection_buckets[dt_truncated] += row.get('hourly_count')
    
    
    all_times = sorted(set(detection_buckets.keys()))
    
    # Step 4: Build labels and aligned data
    labels = [dt.strftime('%Y-%m-%d %H') for dt in all_times]
    detection_counts = [detection_buckets.get(dt, 0) for dt in all_times]

    
    # Step 5: Prepare chart data
    data = [
        {
            "label": "Detections",
            "data": detection_counts,
            "borderColor": "#e74c3c"
        }
    ]


    return {"result": {"labels": labels, "data": data}}
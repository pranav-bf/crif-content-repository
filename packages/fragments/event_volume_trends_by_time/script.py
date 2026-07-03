from datetime import datetime
from collections import defaultdict

# Format: Specifies the format for the data.
def format():
    return "line"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select minute_window,total_count AS total_events FROM streamx_trends_minute where stattype= :stattype ORDER BY  minute_window ASC",
        "parameters": {"stattype":"PUBLISHED"}
    }


def render(results):

    if not results or len(results) == 0:
        raise Exception("No time buckets found in query")
    

    
    # Step 2: Create buckets for timestampbyhour (total events)
    event_buckets = defaultdict(int)
    
    for row in results:
        ts = row.get('minute_window')
        if ts is not None:
            # Remove timezone (anything after + or -)
            # Example: "2025-11-13T19:30:00.000+00:00" → "2025-11-13T19:30:00.000"
            if "+" in ts:
                ts_clean = ts.split("+")[0]
            elif "-" in ts[10:]:   # avoid splitting the date part
                ts_clean = ts.rsplit("-", 1)[0]
            elif ts.endswith("Z"):
                ts_clean = ts[:-1]
            else:
                ts_clean = ts
            dt = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S.%f")
            dt_truncated = dt.replace(minute=0, second=0, microsecond=0)
            event_buckets[dt_truncated] = row.get('total_events', 0)
    
    # Step 3: Combine all unique time keys from both buckets
    all_times = sorted(set(event_buckets.keys()))
    
    # Step 4: Build labels and aligned data
    labels = [dt.strftime('%Y-%m-%d %H') for dt in all_times]
    total_event_counts = [event_buckets.get(dt, 0) for dt in all_times]

    
    # Step 5: Prepare chart data
    data = [
        {
            "label": "Total Event",
            "data": total_event_counts,
            "borderColor": "#3498db"
        }
    ]

    


    return {"result": {"labels": labels, "data": data}}
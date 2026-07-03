from datetime import datetime
from collections import defaultdict

# Format: Specifies the format for the data.
def format():
    return "line"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select timestampbyhour,COUNT(*) AS total_events FROM aggregation_table WHERE provider IS NOT NULL AND type = :type GROUP BY  timestampbyhour ORDER BY  timestampbyhour ASC",
        "parameters": {"type":"tenant_health_monitor_breakdown"}
    }


def render(results):

    if not results or len(results) == 0:
        raise Exception("No time buckets found in query")

    
    # Step 2: Create buckets for timestampbyhour (total events)
    event_buckets = defaultdict(int)
    
    for row in results:
        ts = row.get('timestampbyhour')
        if ts is not None:
            dt = datetime.utcfromtimestamp(ts / 1000)
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






from collections import defaultdict
from datetime import datetime, timedelta

def configure():
    """
    Returns default configuration of the widget.

    Returns:
        dict: Widget layout, filters, type, and search options.
    """
    return {
        "searchable": False,
        "datepicker": True,
        "properties": {"type": "summary", "layout": "analyticslayout","graphtype":"logstable","customDateVisibleOnly": True},
        "filters": [],
        "dimension": {"x": 0, "y": 6, "width": 12, "height": 4}
    }

def query():
    """
    Main query used to fetch data for the widget.

    Returns:
        dict: SQL query and parameter placeholders.
    """
    return [{
            "query": "select hour_bucket  as hour_bucket,SUM(event_count) AS total_count FROM rawevents_hourly_agg GROUP BY hour_bucket ORDER BY hour_bucket desc",
            "parameters": {},
    },
            {
            "query": "select * from implicit_algorithm",
            "parameters": {},
    }]

def filters(filters):
    """
    Query fragments and parameters for user-selected filters.

    Args:
        filters (dict): Filter values selected by the user.

    Returns:
        dict or None: Query parts and parameters or None if filters not used.
    """
    # Return None if filters are not required
    return None

def search(freetext):
    """
    Free-text search support for widget.

    Args:
        freetext (str): User-entered search string.

    Returns:
        dict or None: Search query and parameters, or None if not searchable.
    """
    # Return None if search is not needed
    return None

def sort():
    """
    Sorting logic for the results.

    Returns:
        dict or None: Sorting preferences or None if not applicable.
    """
    return {
        "column": "",
        "order": "asc"
    }

def render(results):

    eventlogs=results[0]
    epslimit = results[1][0] if results[1] else 0
    grouped = defaultdict(list)
    
    # Group data by date
    for row in eventlogs:
        hour_bucket = row.get("hour_bucket")
        total_count = int(row.get("total_count", 0))

        dt = datetime.utcfromtimestamp(int(hour_bucket) / 1000.0)
        dt = dt + timedelta(hours=5, minutes=30)

        date_key = dt.strftime("%Y-%m-%d")
        hour = dt.hour

        grouped[date_key].append({
            "hour": hour,
            "count": total_count
        })

    series = []

    for date_key, values in grouped.items():

        trend = [0] * 24
        spike_trend = [False] * 24

        total = 0
        spike = False

        for item in values:
            hour = item["hour"]
            count = item["count"]

            trend[hour] = count
            total += count

            # Spike condition
            if count > epslimit*60*60:
                spike_trend[hour] = True
                spike = True

        avgEph = round(total / 24.0, 2)

        status = "SPIKE" if spike else "STABLE"

        series.append({
            "date": date_key,
            "total": total,
            "avgeph": avgEph,
            "status": status,
            "spike": spike,
            "hourly_trend": trend,
            "spike_trend": spike_trend
        })

    series = sorted(series, key=lambda x: x["date"], reverse=True)

    return {
        "result": {
            "series": series,
            "epslimit":epslimit
        }
    }


def algorithm():
    tenant = parameters.get("tenant")
  
    return internalServiceClient.epsLimit(tenant)

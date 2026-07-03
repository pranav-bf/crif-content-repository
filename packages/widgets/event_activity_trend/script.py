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
        "properties": {"type": "summary", "layout": "analyticslayout","graphtype":"trend","customDateVisibleOnly": True},
        "filters": [],
        "dimension": {"x": 4, "y": 0, "width": 8, "height": 2}
    }

def query():
    """
    Main query used to fetch data for the widget.

    Returns:
        dict: SQL query and parameter placeholders.
    """
    return {
            "query": "select hour_bucket AS hour_ts,SUM(event_count) AS event_count FROM rawevents_hourly_agg GROUP BY hour_ts ORDER BY hour_ts desc",
            "parameters": {},
    }

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

    event_data = []
    categories = []

    for item in results:
        event_data.append(int(item.get("event_count", 0)))

        hour_ts = int(item.get("hour_ts"))

        # UTC -> IST
        dt = datetime.utcfromtimestamp(hour_ts / 1000.0)
        dt = dt + timedelta(hours=5, minutes=30)

        categories.append(dt.strftime("%m-%d %H:%M"))

    total_events = sum(event_data)

    series = [{
        "data": event_data,
        "color": "#ff7300",
        "name": "Events"
    }]

    return {
        "result": {
            "series": series,
            "categories": categories,
            "total_events": total_events
        }
    }
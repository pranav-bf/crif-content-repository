def configure():
    """
    Returns default configuration of the widget.

    Returns:
        dict: Widget layout, filters, type, and search options.
    """
    return {
        "searchable": False,
        "datepicker": True,
        "properties": {"type": "summary", "layout": "analyticslayout","graphtype":"total events","customDateVisibleOnly": True},
        "filters": [],
        "dimension": {"x": 0, "y": 0, "width": 4, "height": 2}
    }

def query():
    """
    Main query used to fetch data for the widget.

    Returns:
        dict: SQL query and parameter placeholders.
    """
    return [{
            "query": "select tenant,SUM(event_count) AS event_count FROM rawevents_hourly_agg GROUP BY tenant",
            "parameters": {},
    },
            {
            "query": "SELECT * FROM fn_get_two_day_event_change",
            "parameters": {'n' : 0},
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

    # Extract first query result
    totalevents = results[0][0].get("event_count", 0)

    # Extract second query result
    lastevent = results[1][0].get("pct_change")


    if not lastevent:
      lastevent = 0


    return {
        "result": {
            "total": totalevents,
            "lastevent": lastevent
        }
    }
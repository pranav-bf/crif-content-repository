def configure():
    """
    Returns default configuration of the widget.

    Returns:
        dict: Widget layout, filters, type, and search options.
    """
    return {
        "searchable": False,
        "datepicker": True,
        "properties": {"type": "summary", "layout": "analyticslayout","graphtype":"table","customDateVisibleOnly": True},
        "filters": [],
        "dimension": {"x": 0, "y": 2, "width": 12, "height": 4}
    }

def query():
    """
    Main query used to fetch data for the widget.

    Returns:
        dict: SQL query and parameter placeholders.
    """
    return [
      {
            "query": "select grp,provider,event_type,SUM(event_count) AS total_count FROM rawevents_hourly_agg GROUP BY grp, provider, event_type ORDER BY total_count DESC",
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

def render(results):

    data_list = results[0]
    status_list = results[1]

    # Create lookup for status
    status_lookup = {}

    for item in status_list:
        key = (
            str(item.get("provider", "")).lower(),
            str(item.get("group", "")).lower(),
            str(item.get("type", "")).lower(),
        )

        status_lookup[key] = item.get("status", "INACTIVE")

    series = []

    for item in data_list:
        provider = item.get("provider", "")
        grp = item.get("grp", "")
        event_type = item.get("event_type", "")

        key = (
            str(provider).lower(),
            str(grp).lower(),
            str(event_type).lower(),
        )

        status = status_lookup.get(key, "INACTIVE")

        series.append({
            "event_source": provider,
            "grp": grp,
            "event_type": event_type,
            "status": status,
            "total": item.get("total_count", 0),
            "streamprovider": provider 
        })
        

    return {
        "result": {
            "series": series,
            "className": "bxDashboardAnalyticsTableHeaderLayout"
        }
    }


def algorithm():
    tenant = parameters.get("tenant")
  
    return internalServiceClient.getActiveNodes(tenant)
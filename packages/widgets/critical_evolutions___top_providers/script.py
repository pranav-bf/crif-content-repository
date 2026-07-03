import time

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": False,
        "pagination": False,
        "properties": {"type": "column"},
        "dimension": {"x": 4, "y": 3, "width": 8, "height": 2},
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": """
            SELECT
                streamprovider,
                date_trunc('hour', insert_date) AS interval_start,
                COUNT(*) AS event_count
            FROM detection
            WHERE insert_date >= NOW() - INTERVAL '30 days'
            GROUP BY streamprovider, interval_start
            HAVING COUNT(*) > 0
            ORDER BY interval_start, streamprovider;
        """,
        "parameters": {},
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None

# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort():
    return None

# this to return formatted results to render a widget
def render(results):
    from collections import defaultdict

    # Group rows by interval
    interval_groups = defaultdict(list)
    for row in results:
        interval = row["interval_start"]
        interval_groups[interval].append(row)

    # Sorted list of all intervals
    categories = sorted(interval_groups.keys())

    # Initialize provider data structure
    provider_series = defaultdict(lambda: [0] * len(categories))

    # Fill in counts for each provider at each interval
    for idx, interval in enumerate(categories):
        for row in interval_groups[interval]:
            provider = row["streamprovider"]
            count = row["event_count"]
            provider_series[provider][idx] = count

    # Only include providers with at least one non-zero entry
    final_series = [
        {"name": provider, "data": data}
        for provider, data in provider_series.items()
        if any(count > 0 for count in data)
    ]
    legends= [{
  "layout": 'vertical',
  "align": 'right',
  "verticalAlign": 'middle',
  "itemMarginTop": 5,
  "itemStyle": {
    "color": '#888888',
    "fontWeight": 'normal',
    "fontSize": '12px'
  },
  "symbolHeight": 12,
  "symbolWidth": 12,
  "symbolRadius": 6
}]

    return {
        "result": {
            "categories": categories,
            "series": final_series
        },
        "column": "streamprovider",
        "label": "Active Providers per 1-Hour Interval (Last 30 Days)",
        "uniquekey": ["category", "name"],
        "columnmap": ["streamprovider"],
        "legends":legends
    }

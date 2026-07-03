# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": False,
        "properties": {"type": "areastackedchart","layout": "conciselayout"},
        "dimension": {"x":0,"y":1,"width": 8, "height": 2}
    }

# this to return query to be used for rendering widget and its parameters

def query():
    return {
        "query": """
            SELECT
                DATE_TRUNC('hour', insert_date) AS hour,
                criticality,
                COUNT(*) AS event_count
            FROM
                detection
            WHERE
                criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
            GROUP BY
                hour, criticality
            ORDER BY
                hour DESC;
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

def render(result):
    import datetime

    # Collect unique hours and sort them
    unique_hours_set = set()
    for item in result:
        unique_hours_set.add(item['hour'])
    unique_hours = sorted(unique_hours_set)

    # Format categories as strings
    categories = []
    for hour in unique_hours:
        if isinstance(hour, datetime.datetime):
            categories.append(hour.strftime('%Y-%m-%d %H:%M'))
        else:
            categories.append(str(hour))

    # Initialize empty series map
    criticalities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    series_map = {}
    for crit in criticalities:
        series_map[crit] = [0] * len(categories)

    # Map hour to index
    hour_index = {hour: idx for idx, hour in enumerate(unique_hours)}

    # Fill series data
    for item in result:
        crit = item['criticality']
        hour = item['hour']
        count = item['event_count']
        if crit in series_map and hour in hour_index:
            series_map[crit][hour_index[hour]] = count

    # Convert to series list in stacking order (low to high)
    series = []
    for crit in criticalities:
        series.append({
            "name": crit,
            "data": series_map[crit]
        })

    # Updated color gradient (from light to dark like the image)
    colors = [
        "#00b8d3",  # LOW - Pale electric blue
        "#aed987",  # MEDIUM - Pale apple green
        "#eacc62",  # HIGH - Warm mustard yellow
        "#e4604e"   # CRITICAL - Warm reddish-orange
    ]

    # Clean legend layout
    legends = [{
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

    return {"result":{
        "series": series,
        "categories": categories,
        "legends": legends,
        "colors": colors,
        "className": "dlp-dashboardwidgets",
        "xAxis": {
            "labels": {
                "enabled": True,
                "rotation": -45
            }
        },
        "yAxis": {
            "title": {
                "text": "Count"
            }
        }}
    }

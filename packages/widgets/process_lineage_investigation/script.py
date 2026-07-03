# this to return default widget config
from datetime import datetime

def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "fatalwidget","layout": "conciselayout"},
        "dimension": {"x": 0, "y": 9, "width": 8, "height": 3} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT severity_name AS criticality, display_name AS name,hostname as hostname, tactic as tactic,max(timestamp) as lastseen, count(*) AS count FROM aggregation_table WHERE severity_name != :severity_name and  type = :type GROUP BY severity_name, display_name, hostname,tactic",
        "parameters": {"type":"crowdstrike_alert_monitoring","severity_name":"Informational"},
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None

# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort():
    return{
        "sortcol":"count",
        "sortorder":"desc"    
    }


def render(results):
    if len(results) > 10:
        results = results[:10]  # Limit to the first ten records        

    # Convert milliseconds timestamp to formatted date-time
    for row in results:
        if "lastseen" in row and row["lastseen"]:
            row["lastseen"] = datetime.fromtimestamp(row["lastseen"] / 1000).strftime("%Y-%m-%d %H:%M:%S")

    columnList = ['name', 'hostname', 'tactic', 'lastseen', 'criticality', 'count']
    
    return {
        "result": results,
        "columns": columnList,
        "type": "crowdstrike_alert_monitoring"
    }
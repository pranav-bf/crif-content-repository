import time
import re
from collections import defaultdict
import datetime



def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "properties": {"type": "statcard","layout":"card","graphtype":"donut"},
        "dimension": {"x": 9, "y": 0, "width": 3, "height": 1} #dimensions of widget on GRID
    }

  
def query():
    return { "query": 'SELECT "resolution" as obtainedresolution, COUNT(*) AS total_events FROM aggregation_table where type= :type GROUP BY resolution', 'parameters': {"type":"crowdstrike_specific_alert__monitoring"} }


 
# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None
# this to return free text search query and its parameters
def search(freetext):
    return None



# this to return sort query
def sort():
    return None


def render(results):
    print(results)

    total_alerts = 0
    series = {}

    # Process query results
    for row in results:
        resolution = row.get("obtainedresolution")
        count = row.get("total_events", 0)

        series[resolution] = count
        total_alerts += count

    # If no results at all → return zero structure
    if not series:
        percentage_data = {
            "closed": 0,
            "resolved": 0,
            "ignored": 0,
            "false_positive": 0
        }
        total_alerts = 0
    else:
        # Calculate percentages
        percentage_data = {}

        for key, value in series.items():
            if total_alerts > 0:
                percentage = round((float(value) / float(total_alerts)) * 100, 2)
            else:
                percentage = 0

            percentage_data[key] = percentage

    # Fixed color mapping
    colors = {
        "closed": "#4caf50",
        "resolved": "#2196f3",
        "ignored": "#ff9800",
        "false_positive": "#9c27b0"
    }

    return {
        "result": {
            "series": [{
                "name": "Alerts by Resolution Status",
                "data": percentage_data
            }],
            "total": total_alerts,
            "colors": colors,
            "className": "resolution-dashboardstats"
        }
    }


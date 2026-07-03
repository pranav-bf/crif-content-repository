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

  
# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "select distinct(detectionname) from entityscoring;",
          'parameters': {}
    }
 
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
    total_detection_names = len(results)
    max_reference = 500.0  # ensure float division in Python 2

    # Calculate percentage
    percentage = round((total_detection_names / max_reference) * 100, 2)

    # Cap at 100
    if percentage > 100:
        percentage = 100

    series = {
        "Coverage": percentage,
        "Remaining": round(100 - percentage, 2)
    }

    colors = {
        "Coverage": "#00876c",     # filled portion (green)
        "Remaining": "#e4604e"     # background portion (red)
    }

    return {
        "result": {
            "series": [{
                "name": "Threat Coverage",
                "data": series
            }],
            "total": "{0}%".format(percentage),  
            "colors": colors,
            "className": "dlp-dashboardstats"
        }
    }

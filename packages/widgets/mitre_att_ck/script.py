# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": True,
        "properties": {"type": "donut","layout": "conciselayout"},
        "dimension": {"x": 8, "y": 1, "width":4, "height": 2} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT detectiontechnique AS technique,  COUNT(idx) AS total FROM entityscoring WHERE detectiontechnique IS NOT NULL GROUP BY detectiontechnique",
        "parameters": {},
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None

# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort():
    return {
        "sortcol":"technique",
        "sortorder":"DESC"
    }

# this to return return formated results to render a widget
def render(results):
  # Take only the first 5 records
    limited_results = results[:5]
    series = {item["technique"]: item["total"] for item in limited_results}

    return {
        "result": series,
        "showDataLabels": "false",
        "showLegends": "true",
        "stattype": "showLegendsRightSide",
        "circleSize":'increase-circle-size',
        "labelLimit":'10'
    }
# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": True,
        "properties": {"type": "donut","layout": "conciselayout"},
        "dimension": {"x": 8, "y": 2, "width": 4, "height": 2} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT distinct asigneetype , COUNT(*) AS assigneetypecount FROM incidentdetails GROUP BY asigneetype",
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
        "sortcol":"assigneetypecount",
        "sortorder":"DESC"
    }

# this to return return formated results to render a widget
def render(results):
    series = {item["asigneetype"]: item["assigneetypecount"] for item in results}

    return {"result": series}
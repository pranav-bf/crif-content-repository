# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "mitre"},
        "dimension": {"x": 0, "y": 8, "width": 12, "height": 6} #dimensions of widget on GRID
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "select * from implicit_algorithm",
        "parameters": {}
    }
def algorithm():
    return threatCoverage.getMapping()

# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None
# this to return free text search query and its parameters
def search(freetext):
    return None

def sort():
    return None

# this to return return formated results to render a widget
def render(results):
    if not results or len(results) == 0:
        raise Exception("no results found")

    
    return {"result":results}

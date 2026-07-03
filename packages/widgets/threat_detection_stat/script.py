# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "properties": {"type": "statcard","layout":"card","graphtype":"bar"},
        "dimension": {"x": 3, "y": 0, "width": 3, "height": 1} #dimensions of widget on GRID
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT detectioncriticality ,count(*) as criticalitycount FROM entityscoring group by detectioncriticality",
        "parameters": {}
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

# this to return return formated results to render a widget
def render(results):
    categories = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    series = []
    total = 0
    
    # Create a dictionary to map criticality to its count
    criticality_map = {item["detectioncriticality"]: item["criticalitycount"] for item in results}
    
    # Fetch scores in the specified order
    for category in categories:
        series.append(criticality_map.get(category, 0))
        total += criticality_map.get(category, 0)
    
    return {"result": {"series": [{'data': series, "name": 'Detections'}], "categories": categories, "total": total}}

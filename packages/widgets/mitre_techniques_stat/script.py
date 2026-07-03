# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "properties": {"type": "statcard","layout":"card","graphtype":"bar"},
        "dimension": {"x": 0, "y": 0, "width": 3, "height": 1} #dimensions of widget on GRID
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT detectiontechnique,CASE MAX(CASE detectioncriticality WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 0 END) WHEN 3 THEN 'CRITICAL' WHEN 2 THEN 'HIGH' WHEN 1 THEN 'MEDIUM' WHEN 0 THEN 'LOW' END AS detectioncriticality FROM entityscoring WHERE detectiontechnique IS NOT null GROUP BY detectiontechnique",
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
    
    categories=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    counts = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
    }
    for entry in results:
        criticality = entry["detectioncriticality"]
        if criticality in counts:
            counts[criticality] += 1
    
    # Extract counts into a list
    series = [counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]]
    total = sum(series)
    
    return {"result":{"series":[{'data':series,"name": 'Technique'}],"categories":categories,"total":total}}
# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "properties": {"type": "statcard","layout":"card","graphtype":"bar"},
        "dimension": {"x": 6, "y": 0, "width": 3, "height": 1} #dimensions of widget on GRID
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT * from fn_topoutliers",
        "parameters": {'n' : 0}
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
    # Define the categories in the desired order
    categories = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    # Initialize counts list with zeros
    series = [0] * len(categories)
    
    # Count occurrences of each criticality
    for result in results:
        criticality = result.get('criticality')
        if criticality in categories:
            index = categories.index(criticality)
            series[index] += 1

    total=sum(series)
    
    return {"result":{"series":[{'data':series,"name": 'Entity'}],"categories":categories,"total":total}}
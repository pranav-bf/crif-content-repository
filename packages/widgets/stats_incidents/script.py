# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "properties": {"type": "statcard","layout":"card","graphtype":"trend"},
        "dimension": {"x": 9, "y": 0, "width": 3, "height": 1} #dimensions of widget on GRID
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT * from fn_incidents_stats",
        "parameters": {}
    }
 
# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None
# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort(sorcol, sortorder):
    sort += " order by " + sorcol + " " + sortorder

# this to return return formated results to render a widget
def render(results):
    results = sorted(results, key=lambda x: x["timestamp_minute"])

    categories = []
    incident_data = []
    series = []
    total = 0

    for result in results:
        
        date = result.get('timestamp_minute') 
        if date not in categories: 
                categories.append(date)
        
        incident_data.append(result["total_count"])
        total += result["total_count"]
       
    
    series.append({"name": "INCIDENTS","data": incident_data})
    
    return {"result":{"categories":categories,"series":series,"total":total}}

   
           
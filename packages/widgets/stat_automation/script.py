# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "properties": {"type": "statcard","layout":"card","graphtype":"trend"},
        "dimension": {"x": 6, "y": 0, "width": 3, "height": 1} #dimensions of widget on GRID
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT * from fn_statcard",
        "parameters": {"stattype":"AUTOMATIONS"}
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
    results = sorted(results, key=lambda x: x["publish_date"])

    categories = []
    automation_data = []
    series = []
    total = 0

    for result in results:
        
        date = result.get('publish_date') 
        if date not in categories: 
                categories.append(date)
        
        automation_data.append(result["cumulative_sum"])
        total += result["cumulative_sum"]
       
    
    series.append({"name": "AUTOMATIONS","data": automation_data})
    
    return {"result":{"categories":categories,"series":series,"total":total}}

           
           
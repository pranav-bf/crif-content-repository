# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": True,
        "properties": {"type": "bar","layout": "conciselayout","onclick":"not_open_offcanvaspanel"},
        "dimension": {"x": 4, "y": 2, "width": 4, "height": 2} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT distinct assignee , COUNT(*) AS assigneecount FROM incidentdetails GROUP BY assignee",
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
        "sortcol":"assigneecount",
        "sortorder":"DESC"
    }


# this to return return formated results to render a widget
def render(result):
    data = []
    categories = []
    counter=0

    for item in result:
        if(counter<5):
            categories.append(item["assignee"])
            data.append(item["assigneecount"])
            counter=counter+1
        
    return {"result":{"series":[{'data':data}], 'categories': categories}}
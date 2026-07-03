# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "line","layout": "conciselayout"},
        "dimension": {"x": 4, "y": 4, "width": 4, "height": 2} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT * FROM fn_getdetectionincidentcounts",
        "parameters": {'n' : 0},
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
    
    if not results or len(results) == 0:
        raise Exception("no results found")
    
    categories=[]
    data=[]
    series=[]
    counter=0

    for result in results :
        if(counter<5):
          categories.append(result.get('detection_name'))
          data.append(result.get('incidents_count'))
          counter=counter+1
    
    seriesObj={
        "name":"detections",
        "data":data,
        "color":"#ff7300"
    }

    series.append(seriesObj)
    
    return {"result":{"categories":categories,"series":series}}



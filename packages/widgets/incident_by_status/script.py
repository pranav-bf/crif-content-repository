# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "properties": {"type": "singlecolumn","layout":"conciselayout"},
        "dimension": {"x":4,"y":0,"width": 4, "height": 2}
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": " SELECT distinct status, COUNT(*) AS statuscount FROM incidentdetails GROUP BY status",
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
        "sortcol":"statuscount",
        "sortorder":"DESC"
    }

# this to return return formated results to render a widget
def render(data):
  
    categories = [item["status"] for item in data]
    series = [item["statuscount"] for item in data]
    
    return {"result":{"series":series,"categories":categories}}
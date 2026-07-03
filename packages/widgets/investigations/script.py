# this to return default widget config
def configure():
    return {
        "searchable": True,
        "datepicker": False,
        "properties": {"type": "my_queue"},
        "dimension": {"x": 0, "y": 0, "width": 4, "height": 6}
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "select * from fn_topqueues",
        "parameters": {}
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filters):

  return None

# this to return free text search query and its parameters
def search(freetext):
    searchquery = " name ilike :name or status ilike :name "
    return {
        "searchquery": searchquery,
        "parameters": {"name": "%" + freetext + "%"},
    }


# this to return sort query
def sort():
    return None

# this to return return formated results to render a widget
def render(results):
    return  {"result":results}
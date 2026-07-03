# this to return default widget config
def configure():
    return {
        "searchable": True,
        "datepicker": True,
        "properties": {"type": "table"},
        "filters":None,
        "dimension": {"x": 4, "y": 21, "width": 4, "height": 5}
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT * from fn_topoutliers",
        "parameters": {'n' : 0,'badge':['Watchlist']},
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    filterqueries = []
    parameters = {}
    if filter:
        if filter.get("badge"):
            parameters["badge"] = filter.get("badge")
        
    return {"filterqueries": filterqueries, "parameters": parameters}

# this to return free text search query and its parameters
def search(freetext):
    searchquery = ' "entity" ilike :_entity '
    return {
        "searchquery": searchquery,
        "parameters": {"_entity": "%" + freetext + "%"},
    }

# this to return sort query
def sort(sorcol, sortorder):
    sort += " order by " + sorcol + " " + sortorder


# this to return return formated results to render a widget
def render(results):

    if not results or len(results) == 0:
        raise Exception("no results found")
    
    for result in results:
        result['description']=graph.getMeta(result['entity'],result['entitytype'])
    
    columns = ['entity' , 'score']

    return  {"result":{"columns": columns, "rows": results}}

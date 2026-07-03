# sample name -> widgets/accounts_compromised/script.py
# this to return default widget config
def configure():
    return {
        "searchable": True,
        "datepicker": True,
        "properties": {"type": "table"},
        # "filters":['widgetfilters/criticality_filter/','widgetfilters/tactic_filter/',
                #    'widgetfilters/technique_filter/','widgetfilters/stream_filter/'],
        "dimension": {"x":0,"y":1,"width": 4, "height": 7}
    }


# this to return query to be used for rendering widget and its parameters
def query():

    # return {
    #     "query": "SELECT detectionname as name, 'detection' as type , detectionid as id , COUNT(DISTINCT entity) AS entities, tenant, detectiontactic, detectiontechnique, streamid FROM entityscoring WHERE detectionname IS NOT NULL GROUP BY name , id , tenant, detectiontactic, detectiontechnique, streamid ORDER BY entities DESC",
    #     "parameters": {}
    # }

    return {
        "query": "SELECT * from fn_topdetections",
        "parameters": {"n":0}
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    filterqueries = []
    parameters = {}
    if filter:
        if filter.get("detectioncriticality"):
            parameters["criticality"] = filter.get("detectioncriticality")
        if filter.get("detectiontactic"):
            parameters["tactic"] = filter.get("detectiontactic")
        if filter.get("detectiontechnique"):
            parameters["technique"] = filter.get("detectiontechnique")
        if filter.get("streamname"):
            parameters["streamname"] = filter.get("streamname")
    return {"filterqueries": filterqueries, "parameters": parameters}


# this to return free text search query and its parameters
def search(freetext):
    searchquery = '"name" ilike :name '
    return {
        "searchquery": searchquery,
        "parameters": {"name": "%" + freetext + "%"},
    }


# this to return sort query
def sort(sorcol, sortorder):
    sort += " order by " + sorcol + " " + sortorder


# this to return return formated results to render a widget
def render(results):

    if not results or len(results) == 0:
        raise Exception("no results found")
    
    for result in results:
        result['description'] = result['detectiontechnique'] + ' | ' + result['detectiontactic']

    rows = []
    columns = ['name' , 'entities']

    return  {"result":{"columns": columns, "rows": results}}

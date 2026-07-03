# sample name -> widgets/accounts_compromised/script.py


# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepiacker":True,
        "properties": {"type": "scatterplot"},
        "dimension": {"x": 4, "y": 14, "width": 8, "height": 4}
    }


# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": "SELECT DISTINCT entity, entitytype, tenant, sum(score) as total_score, count(detectionid) as detection_count, CASE MAX(CASE detectioncriticality WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 0 END) WHEN 3 THEN 'CRITICAL' WHEN 2 THEN 'HIGH' WHEN 1 THEN 'MEDIUM' WHEN 0 THEN 'LOW' END AS detectioncriticality, 'entity' AS type FROM entityscoring GROUP BY entity, entitytype, tenant;",
        "parameters": {},
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filters):

    
    return None


# this to return free text search query and its parameters
def search(freetext):
   
    return None

def sort():
    return{
        "sortcol":"total_score",
        "sortorder":"desc"    
    }


# this to return return formated results to render a widget
def render(results):

    return  {"result":results}
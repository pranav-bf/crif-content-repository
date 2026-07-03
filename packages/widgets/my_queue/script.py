# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": True,
        "datepicker": True,
        "properties": {"type": "my_queue"},
        "dimension": {"x": 0, "y": 21, "width": 4, "height": 5}
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "select * from fn_topqueues",
        "parameters": {}
    }
    # return {
    #     "query": "select * , 'incident' as type, CASE WHEN criticality = 'HIGH' THEN '#FF0000' WHEN criticality = 'MEDIUM' THEN '#FFA500' WHEN criticality = 'LOW' THEN '#008000' ELSE '#FFFF00' END AS color from incidentdetails where completed = false and ((asigneetype = 'group' and assignee = ANY(:groups)) or (asigneetype = 'user' and assignee = :username))",
    #     "parameters": {'contextparameters':['groups','username'],'usercontext':True}
    # }



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
    return {
        "sortcol":"createdon",
        "sortorder":"DESC"
    }

# this to return return formated results to render a widget
def render(results):
    return  {"result":results} 
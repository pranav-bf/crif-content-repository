# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "properties": {"type": "pie","onclick":"filter_not_apply"},
        "dimension": {"x":0,"y":14,"width": 4, "height": 4}
    }

# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": "SELECT detectiontactic AS tactic,  COUNT(idx) AS total FROM entityscoring WHERE detectiontactic IS NOT NULL GROUP BY tactic",
        "parameters": {}
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filters):

    return None


# this to return free text search query and its parameters
def search(freetext):
    return None

def sort():
    return{
        "sortcol":"total",
        "sortorder":"desc"    
    }


# this to return return formated results to render a widget
def render(data):
    transformed_data = []

    for item in data:
        transformed_data.append({
            "name": item["tactic"],
            "y": item["total"]
        })
    
    return {"result":transformed_data}

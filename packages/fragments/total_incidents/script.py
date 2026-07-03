# Format: Specifies the format for the data.

def format():
    return "statcard"

# Query: Specifies the query to retrieve data.

# Query: Fetch detection tactic, detection name, and total count
def query():

    return {
        "query": "SELECT count(*) as total_incident from incidentdetails ",
        "parameters": {}
    }
  

def render(results):

    total = results[0]["total_incident"]   # extract from first row

    return {
        "result": {
            "labels": ["Incidents"],
            "data": [
                {
                    "label": "Incidents",
                    "data": [total]
                }
            ]
        }
    }
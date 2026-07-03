# Format: Specifies the format for the data.

def format():
    return "statcard"

# Query: Specifies the query to retrieve data.

# Query: Fetch detection tactic, detection name, and total count
def query():

    return [{
        "query": "SELECT SUM(statcount) AS total_count from streamx WHERE stattype = :stattype",
        "parameters": {"stattype":"DETECTIONS"}
    },{
        "query": "SELECT count(*) as total_incident from incidentdetails ",
        "parameters": {}
    }]
  

def render(results):

    total_count = results[0][0]["total_count"]
    total_incident = results[1][0]["total_incident"]

    falsepositive = total_count - total_incident

    return {
        "result": {
            "labels": ["False Positives"],
            "data": [
                {
                    "label": "False Positives",
                    "data": [falsepositive]
                }
            ]
        }
    }

# Format: Specifies the format for the data.

def format():
    return "statcard"

# Query: Specifies the query to retrieve data.

# Query: Fetch detection tactic, detection name, and total count
# Query: Specifies the query to retrieve data.
def query():

    return {
        "query": "SELECT SUM(statcount) AS total_count  from streamx WHERE stattype = :stattype",
        "parameters": {"stattype":"DETECTIONS"}
    }
def _format_number(num):
    try:
        num = float(num)
    except:
        return num

    if num >= 1000000000:
        return "{:.1f}B".format(num / 1000000000.0)
    elif num >= 1000000:
        return "{:.1f}M".format(num / 1000000.0)
    elif num >= 1000:
        return "{:.1f}K".format(num / 1000.0)
    else:
        return int(num) 
      
def render(results):

    return {
        "result": {
            "labels": ["Detections"],      # TITLE of statcard
            "data": [
                {
                    "label": "Detections",
                    "data": [_format_number(results[0]["total_count"])]    # ONE VALUE ONLY
                }
            ]
        }
    }
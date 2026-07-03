
  
def format():
  return "statcardwithicon"


def query():
  # TODO: Define your SQL query and parameters for the widget.
      return {
                  "query": """ 
                  SELECT COUNT(*) AS total_inprogress_incidents FROM incidentdetails WHERE status = 'In Progress'
        """,
        "parameters": {}
      }


def render(result):
    total = 0
    if result and len(result) > 0:
        total = result[0].get("total_inprogress_incidents", 0)
      
    return {
                  "result": {
                      "labels": ["Total Incident(In Progress)"],      # TITLE of statcard
                      "data": [
                          {
                              "label": "Incident In Progress",
                              "data": [total],
                              "icon": ["hourglass_top"],
                              "iconClass": ["icon-yellow"]
                          }
                      ]
                  }
              }


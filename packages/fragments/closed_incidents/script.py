
  
def format():
  return "statcardwithicon"


def query():
  # TODO: Define your SQL query and parameters for the widget.
      return {
                  "query": """ 
                  SELECT COUNT(*) AS total_closed_incidents FROM incidentdetails WHERE status = 'Close'
        """,
        "parameters": {}
      }


def render(result):
    total = 0
    if result and len(result) > 0:
        total = result[0].get("total_closed_incidents", 0)
      
    return {
                  "result": {
                      "labels": ["Total Incident(Close)"],      # TITLE of statcard
                      "data": [
                          {
                              "label": "Incident Close",
                              "data": [total],
                              "icon": ["check_circle"],
                              "iconClass": ["icon-green"]
                          }
                      ]
                  }
              }


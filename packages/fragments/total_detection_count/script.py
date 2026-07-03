
  
def format():
  return "statcardwithicon"


def query():
    # TODO: Define your SQL query and parameters for the widget.
    return {
        "query": """
              SELECT 
                  COUNT(*) AS total_detection_count
              FROM detection
          """,
          "parameters": {}
    }


def render(result):
    total = 0
    if result and len(result) > 0:
        total = result[0].get("total_detection_count", 0)
      
    return {
                  "result": {
                      "labels": ["Total Detections"],      # TITLE of statcard
                      "data": [
                          {
                              "label": "Detections",
                              "data": [total],
                              "icon": ["schedule"],
                              "iconClass": ["icon-yellow"]
                          }
                      ]
                  }
              }


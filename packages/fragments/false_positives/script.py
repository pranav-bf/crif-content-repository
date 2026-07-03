
  
def format():
  return "statcardwithicon"


def query():
    # TODO: Define your SQL query and parameters for the widget.
    return {
         "query": """
          SELECT 
              COUNT(*) AS total_false_positive
          FROM detection
          WHERE status = 'RCA_IGNORE'
      """,
      "parameters": {}
    }


def render(result):
        total = 0
        if result and len(result) > 0:
            total = result[0].get("total_false_positive", 0)
          
        return {
                      "result": {
                          "labels": ["False Positives"],      # TITLE of statcard
                          "data": [
                              {
                                  "label": "False Positives",
                                  "data": [total],
                                  "icon": ["shield"],
                                  "iconClass": ["icon-blue"]
                              }
                          ]
                      }
                  }


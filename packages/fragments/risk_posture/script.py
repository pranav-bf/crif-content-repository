

  
def format():
  return "statcardwithicon"


def query():
    # TODO: Define your SQL query and parameters for the widget.
    return {
        "query": """
              select * from implicit_algorithm
          """,
          "parameters": {}
    }


def render(result):
    # Default fallback value
    value = 0

    try:
        if result and len(result) > 0:
            query_result = result[0].get("result", [])

            if query_result and len(query_result) > 0:
                value = query_result[0].get("securityposture", 0)

                # Handle None values
                if value is None:
                    value = 0

    except Exception as e:
        print("Error processing result:", e)
        value = 0

    return {
        "result": {
            "labels": ["Risk Posture"],
            "data": [
                {
                    "label": "Risk Posture",
                    "data": [value],
                    "icon": ["health_and_safety"],
                    "iconClass": ["icon-purple"]
                }
            ]
        }
    }



def algorithm():
    starttime = parameters.get("starttime")
    endtime = parameters.get("endtime")
  
    return internalServiceClient.securityPosture(starttime,endtime)
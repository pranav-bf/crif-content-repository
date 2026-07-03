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
    value = 0

    try:
        if result and len(result) > 0:
            query_result = result[0].get("result", 0)

            # If result is already a number
            if isinstance(query_result, (int, float)):
                value = query_result

            # If result is a list of dicts
            elif isinstance(query_result, list) and len(query_result) > 0:
                value = query_result[0].get("threatcoverage", 0)

            if value is None:
                value = 0

    except Exception as e:
        print("Error processing result:", e)
        value = 0

    formatted = "{:.2f}%".format(float(value))

    return {
        "result": {
            "labels": ["Threat Coverage"],
            "data": [
                {
                    "label": "Threat Coverage",
                    "data": [formatted],
                    "icon": ["radar"],
                    "iconClass": ["icon-teal"]
                }
            ]
        }
    }
  
def algorithm():
  
    return threatCoverage.getThreatCoverage()
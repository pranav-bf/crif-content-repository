

  
def format():
  return "statcardwithicon"


def query():
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
            # Handle both formats:
            # [('collectorCount', [9])] OR [9]
    
            first_item = result[0]
    
            if isinstance(first_item, tuple):
                # Format: ('collectorCount', [9])
                collector_data = first_item[1]
    
                if isinstance(collector_data, list) and len(collector_data) > 0:
                    value = collector_data[0]
                else:
                    value = collector_data
    
            elif isinstance(first_item, int):
                # Format: [9]
                value = first_item
    
            elif isinstance(first_item, list) and len(first_item) > 0:
                # Format: [[9]]
                value = first_item[0]
    
            if value is None:
                value = 0
    
    except Exception as e:
        print("Error processing result:", e)
        value = 0
    
    
    return {
        "result": {
            "labels": ["Event Sources"],
            "data": [
                {
                    "label": "Event Sources",
                    "data": [value],  
                    "icon": ["devices"],
                    "iconClass": ["icon-purple"]
                }
            ]
        }
    }



def algorithm():
  
    return internalServiceClient.collectorCount()
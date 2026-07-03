# Format: Specifies the format for the data.
def format():
    return "statcard"


# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": """
            SELECT SUM(privilege_escalations) AS total
            FROM windows_privileged_hourly_activity """,
        "parameters": {}
    }


def render(results):
    print(results)

    total_value = results[0]["total"] if results and results[0]["total"] else 0

    return {
        "result": {
            "labels": ["Privilege Escalations"],
            "data": [
                {
                    "label": "Events",
                    "data": [total_value]
                }
            ]
        }
    }

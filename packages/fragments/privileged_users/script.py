# Format: Specifies the format for the data.
def format():
    return "statcard"


def query():
    
    return {
        "query": """
            SELECT COUNT(DISTINCT source_account_name) AS total
            FROM windows_privileged_hourly_activity
            WHERE privilege_escalations > 0
        """,
        "parameters": {}
    }


def render(results):
    print(results)

    total_value = results[0]["total"] if results and results[0]["total"] else 0

    return {
        "result": {
            "labels": ["Privileged Users Observed"],
            "data": [
                {
                    "label": "Events",
                    "data": [total_value]
                }
            ]
        }
    }

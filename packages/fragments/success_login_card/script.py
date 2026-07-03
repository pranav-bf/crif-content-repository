# Format: Specifies the format for the data.
def format():
    return "statcard"


# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": """
            SELECT SUM(successful_logins) AS total
            FROM windows_privileged_hourly_activity
            WHERE source_account_name IN (
                SELECT DISTINCT source_account_name
                FROM windows_privileged_hourly_activity
                WHERE privilege_escalations > 0
            )
        """,
        "parameters": {}
    }


def render(results):
    print(results)

    total_value = results[0]["total"] if results and results[0]["total"] else 0

    return {
        "result": {
            "labels": ["Successful Logins"],
            "data": [
                {
                    "label": "Events",
                    "data": [total_value]
                }
            ]
        }
    }

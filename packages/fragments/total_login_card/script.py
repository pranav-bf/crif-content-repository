# Format: Specifies the format for the data.
def format():
    return "statcard"


# Query: Specifies the query to retrieve data.
def query():
    
    return [{
        "query": """
            SELECT SUM(total_logins) AS total
            FROM windows_privileged_hourly_activity
            WHERE source_account_name IN (
                SELECT DISTINCT source_account_name
                FROM windows_privileged_hourly_activity
                WHERE privilege_escalations > 0
            )
        """,
        "parameters": {}
    },{
        "query": """
            SELECT SUM(total_logins) AS total
            FROM windows_privileged_hourly_activity
        """,
        "parameters": {}
    }]


def render(results):
    print(results)

    privilege_total_value = results[0][0]["total"] if results and results[0] else 0
    total_value = results[1][0]["total"] if len(results) > 1 and results[1] else 0

    final_value = str(privilege_total_value) + "/" + str(total_value)

    return {
        "result": {
            "labels": ["Total Privileged Logins / Total Logins"],
            "data": [
                {
                    "label": "Events",
                    "data": [final_value]
                }
            ]
        }
    }

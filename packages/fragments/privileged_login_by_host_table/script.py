def format():
    return "tabular"

# Query: Fetch privileged users with at least one successful or failed login
def query():
    return {
        "query": """
           SELECT 
    host AS user,
    SUM(successful_logins) AS successful,
    SUM(failed_logins) AS failed,
      SUM(total_logins) AS total
FROM windows_privileged_hourly_activity
WHERE source_account_name IN (
    SELECT DISTINCT source_account_name
    FROM windows_privileged_hourly_activity
    WHERE privilege_escalations > 0
)
GROUP BY host
HAVING SUM(total_logins) >0
ORDER BY total asc

        """,
        "parameters": {}
    }


def render(results):

    # Table headers
    labels = [
        "Host",
        "Successful Logins",
        "Failed Logins"
    ]

    data = []

    # Take top 10 by login volume
    for row in results[:10]:
        data.append([
            row.get("user"),
            row.get("successful", 0),
            row.get("failed", 0)
        ])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }
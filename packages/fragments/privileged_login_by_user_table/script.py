def format():
    return "tabular"

# Query: Fetch privileged users with at least one successful or failed login
def query():
    return {
        "query": """
           SELECT 
    source_account_name AS user,
    SUM(successful_logins) AS successful,
    SUM(failed_logins) AS failed,
      SUM(total_logins) AS total
FROM windows_privileged_hourly_activity
WHERE source_account_name IN (
    SELECT DISTINCT source_account_name
    FROM windows_privileged_hourly_activity
    WHERE privilege_escalations > 0
)
GROUP BY source_account_name
HAVING SUM(total_logins) >0
ORDER BY total asc

        """,
        "parameters": {}
    }


def render(results):

    # Sort by total logins descending
    sorted_results = sorted(
        results,
        key=lambda r: r.get("total", 0),
        reverse=True
    )

    # Table headers
    labels = [
        "User",
        "Successful Logins",
        "Failed Logins"
    ]

    data = []

    # Take top 10 by login volume
    for row in sorted_results[:10]:
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
def format():
    return "tabular"

# Query: Fetch detection tactic, detection name, and total count
def query():
    return {
        "query": """SELECT 
    source_account_name AS user,
    SUM(privilege_escalations) AS privilege_escalations,
    SUM(privileged_process_events) AS privileged_process_events,
   sum(total_privileged_activity) AS total
FROM windows_privileged_hourly_activity
GROUP BY source_account_name
HAVING sum(total_privileged_activity) > 0
ORDER BY total asc
""",
        "parameters": {}
    }



def render(results):
    print(results)

    # Sort by total descending first
    sorted_results = sorted(
        results,
        key=lambda r: r.get("total", 0),
        reverse=True
    )

    # Table headers
    labels = [
        "User",
        "Privilege Escalations",
        "Privileged Process Events"
    ]

    data = []

    # Take top 10 by total activity
    for row in sorted_results[:10]:
        data.append([
            row.get("user"),
            row.get("privilege_escalations", 0),
            row.get("privileged_process_events", 0)
        ])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }
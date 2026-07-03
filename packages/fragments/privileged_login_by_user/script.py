# Format: Specifies the format for the data.

def format():
    return "bar"



# Query: Fetch detection tactic, detection name, and total count
def query():
    return {
        "query": """select 
    source_account_name as user, 
    sum(successful_logins) as sucessfull,
    sum(failed_logins) as failed,
    sum(total_logins) as total
FROM windows_privileged_hourly_activity
WHERE source_account_name IN (
    SELECT DISTINCT source_account_name
    FROM windows_privileged_hourly_activity
    WHERE privilege_escalations > 0
)
and total_logins > 0
group by source_account_name

order by total desc
limit 5
""",
        "parameters": {}
    }



def render(results):

    labels = []
    successful_data = []
    failed_data = []

    for row in results:
        labels.append(row.get("user"))

        s = int(row.get("sucessfull", 0))
        f = int(row.get("failed", 0))

        # log scale cannot plot 0 → use None so Chart.js skips it
        successful_data.append(s if s > 0 else None)
        failed_data.append(f if f > 0 else None)

    data = [
        {
            "label": "Successful Logins",
            "data": successful_data,
            "backgroundColor": "#60A5FA"
        },
        {
            "label": "Failed Logins",
            "data": failed_data,
            "backgroundColor": "#F87171"
        }
    ]

    options = {
    "scales": {
        "y": {
            "type": "logarithmic",
            "title": {
                "display": True,
                "text": "Login Count (Log Scale)"
            },
            "ticks": {
                "display": True,
                "callback": """
function(value, index, ticks) {
    // show only meaningful tick values
    if (value === 1 || value === 10 || value === 100 || value === 1000 ||
        value === 10000 || value === 100000 || value === 1000000) {
        return Number(value).toLocaleString();
    }
    return '';
}
"""
            }
        }
    }
}

    return {
        "result": {
            "labels": labels,
            "data": data,
            "options": options
        }
    }
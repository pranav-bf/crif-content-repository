from datetime import datetime
def format():
    return "tabular"

def query():
    return {
        "query": "SELECT id AS case_id, name AS title, description, criticality, status, MIN(createdon) AS created, MAX(lastprobetime) AS updated FROM incidentdetails where status != :type GROUP BY id, name, description, criticality, status ORDER BY updated DESC",
        "parameters": {"type": "closed"}
    }



def render(results):

    labels = [
        "Case Id",
        "Detection Title",
        "Detection Description",
        "Severity",
        "Status",
        "Created",
        "Updated"
    ]

    data = []

    if not results:
        return {
            "result": {
                "labels": labels,
                "data": []
            }
        }

    results = results[:5]

    for row in results:
        created_ts = row.get("created")
        if created_ts:
            created = datetime.utcfromtimestamp(created_ts / 1000).strftime("%Y-%m-%d %H:%M")
        else:
            created = "-"

        updated_ts = row.get("updated")
        if updated_ts:
            updated = datetime.utcfromtimestamp(updated_ts / 1000).strftime("%Y-%m-%d %H:%M")
        else:
            updated = "-"

        data.append([
            row.get("case_id", "-"),
            row.get("title", "-"),
            row.get("description", "-"),
            row.get("criticality", "-"),
            row.get("status", "-"),
            created,
            updated
        ])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }

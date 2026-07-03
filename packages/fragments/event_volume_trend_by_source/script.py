


# Format: Specifies the format for the data.

def format():
    return "stackedBar"

# Query: Specifies the query to retrieve data.
def query():
    return [
        {
            "query": "SELECT SUM(statcount) AS total_events, 'Fortigate' AS provider "
                     "FROM streamx WHERE objectid='68a84be658609e155463eac4' GROUP BY provider;"
        },
        {
            "query": "SELECT SUM(statcount) AS total_events, 'Microsoft' AS provider "
                     "FROM streamx WHERE objectid='6852b78bf4b113490cb12cea' GROUP BY provider;"
        },
        {
            "query": "SELECT SUM(statcount) AS total_events, 'Linux' AS provider "
                     "FROM streamx WHERE objectid='6852d65af4b113490cb12d1a' GROUP BY provider;"
        },
        {
            "query": "SELECT SUM(statcount) AS total_events, 'Mac' AS provider "
                     "FROM streamx WHERE objectid='685cf5d1f4b113490cb12e8a' GROUP BY provider;"
        },
        {
            "query": "SELECT SUM(statcount) AS total_events, 'Trellix' AS provider "
                     "FROM streamx WHERE objectid='68775dca54295a253fcd4aad' GROUP BY provider;"
        },
        {
            "query": "SELECT SUM(statcount) AS total_events, 'Sonicawall' AS provider "
                     "FROM streamx WHERE objectid='6855562af4b113490cb12e58' GROUP BY provider;"
        }
    ]
def render(results):
    if not results:
        raise Exception("no results found")

    # Merge all non-empty result lists
    final_rows = []
    for res in results:
        if res:
            final_rows.extend(res)

    if not final_rows:
        raise Exception("no valid rows found")

    labels = []
    total_events = []

    for r in final_rows:
        labels.append(r["provider"])
        total_events.append(r.get("total_events", r.get("total", 0)))

    data = [
        {
            "label": "Events",
            "data": total_events,
            "backgroundColor": "#2ecc71"
        }
    ]

    return {"result": {"labels": labels, "data": data}}




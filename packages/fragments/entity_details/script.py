from datetime import datetime
def format():
    return "tabular"

def query():
    return {
        "query": "SELECT entity, streamprovider, detectioncriticality, COUNT(entity) AS entity_count, MAX(hour_bucket) AS last_seen FROM entity_hourly_summary GROUP BY entity, streamprovider, detectioncriticality ORDER BY entity_count DESC",
        "parameters": {}
    }


def render(results):

    labels = ["ENTITY", "SOURCE", "OCCURRENCES ", "SEVERITY", "LAST SEEN"]
    data = []

    if not results:
        return {
            "result": {
                "labels": labels,
                "data": []
            }
        }

    sorted_results = sorted(
        results,
        key=lambda r: r.get("entity_count", 0),
        reverse=True
    )


    for row in sorted_results[:10]:

               # Format last_seen timestamp
        last_seen_raw = row.get("last_seen")
        if last_seen_raw:
            try:
                # Handle millisecond epoch (e.g. 1738368000000)
                ms_val = int(last_seen_raw)
                dt = datetime.utcfromtimestamp(ms_val / 1000.0)
                last_seen = dt.strftime("%d %b %Y %H:%M")
            except (ValueError, TypeError):
                try:
                    # Fallback: ISO string format
                    dt = datetime.fromisoformat(str(last_seen_raw).replace("Z", "+00:00"))
                    last_seen = dt.strftime("%d %b %Y %H:%M")
                except Exception:
                    last_seen = str(last_seen_raw)
        else:
            last_seen = "-"


        data.append([
            row.get("entity", "-"),
            row.get("streamprovider", "-"),
            row.get("entity_count", 0),
            row.get("detectioncriticality", "-"),
            last_seen
        ])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }

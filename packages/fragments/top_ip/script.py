def format():
    return "tabular"

def query():
    return [{
        "query": "SELECT source_ip, SUM(source_count) AS total_source_count FROM source_ip_daily WHERE source_ip IS NOT NULL AND source_ip != :type GROUP BY source_ip ORDER BY total_source_count DESC",
      "parameters": {"type": "-"},
      "options": {"limit": 10}
    },
    {
      "query": "SELECT destination_ip, SUM(destination_count) AS total_destination_count FROM destination_ip_daily WHERE destination_ip IS NOT NULL AND destination_ip != :type GROUP BY destination_ip ORDER BY total_destination_count DESC",
        "parameters": {"type": "-"},
        "options": {"limit": 10}
    }]

def render(results):
    """
    Expected structure:
    [
        [ {u'source_ip': '...', u'total_source_count': ...}, ... ],
        [ {u'destination_ip': '...', u'total_destination_count': ...}, ... ]
    ]
    """

    combined = []

    # Source IP results
    source_results = results[0]
    for row in source_results:
        if 'source_ip' in row and 'total_source_count' in row:
            ip = row['source_ip']
            count = row['total_source_count']
            if ip is not None:
                combined.append([ip, count])

    # Destination IP results
    destination_results = results[1]
    for row in destination_results:
        if 'destination_ip' in row and 'total_destination_count' in row:
            ip = row['destination_ip']
            count = row['total_destination_count']
            if ip is not None:
                combined.append([ip, count])

    # Sort in descending order by count
    combined.sort(key=lambda x: x[1], reverse=True)

    
    
    # Keep only top 10 overall
    combined = combined[:10]

    for row in combined:
        row[1] = "{:,}".format(int(row[1]))


    labels = ["IP", "Count"]

    return {
        "result": {
            "labels": labels,
            "data": combined
        }
    }

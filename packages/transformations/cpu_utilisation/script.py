import re



def transform(event):
    details = (event.get('message') or '').lower()
    m = re.search(r"cpu_pct=(\d+)", details)
    if m:
        event['cpu_utilisation']=float(m.group(1))

    return event  # Return the enriched event


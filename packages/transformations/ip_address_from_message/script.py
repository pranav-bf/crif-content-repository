import re



def transform(event):
    # raw = event.get('event_details')
    raw = event.get("event_details") or ""
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", raw)
    if m:
        event['source_ip'] = m.group(1)

    return event  # Return the enriched event


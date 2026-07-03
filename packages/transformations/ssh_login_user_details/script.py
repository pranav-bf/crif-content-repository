import re



def transform(event):
    raw = event.get('event_details')
    if raw:
      m = re.search(r"\bfor\s+([A-Za-z0-9_\-]+)\s+from\b", raw)
      if m:
          event['user'] = m.group(1)

    return event


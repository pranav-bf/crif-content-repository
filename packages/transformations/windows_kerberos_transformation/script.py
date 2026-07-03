

def transform(event):
    # TODO: Modify the event as needed
    # Example: event["normalized_username"] = event.get("username", "").lower()
    guids = event.get("event_type")
    if guids:
      guids = str(guids).replace("{", "").replace("}", "").split()
      event['event_type'] = ", ".join(guids);
    return event  # Return the enriched event

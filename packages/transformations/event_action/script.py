import re



def transform(event):
    # details = event.get('event_details')
    # act = re.search(r'\b(Started|Stopped|Deactivated|Failed|Succeeded|resumed|suspended)\b', details, re.I)
    # if act:
    #     event["event_action"] = act.group(1)
    # return event
    details = event.get("event_details") or ""

    match = re.search(
        r"\b(Started|Stopped|Deactivated|Failed|Succeeded|resumed|suspended)\b",
        details,
        re.I
    )

    if match:
        event["event_action"] = match.group(1)

    return event


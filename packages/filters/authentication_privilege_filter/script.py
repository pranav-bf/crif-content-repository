EVENT_IDS = {"4624", "4625", "4672", "4673", "4728", "4729", "1102", "4741"}


def condition(event):
    if event['event_id'] in EVENT_IDS:
        return True
    else:
        return False


EVENT_IDS = {"4688", "4957", "4953", "4663", "4656", "307"}


def condition(event):
    if event['event_id'] in EVENT_IDS:
        return True
    else:
        return False


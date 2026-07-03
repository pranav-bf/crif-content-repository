EVENT_IDS = {"5152", "5157", "7045", "4698", "5145", "4663", "5140", "4625", "805", "808", "4624"}


def condition(event):
    if event['event_id'] in EVENT_IDS:
        return True
    else:
        return False


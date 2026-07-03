
def condition(event):
    if event.get('event_level') != 5 :
        return True
    else:
        return False

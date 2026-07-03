
def condition(event):
      action = (event.get('event_action') or '').lower()
      if action not in ['allow', 'accept', 'permit']:
        return False
      if event.get("destination_ip") and event.get("destination_ip") == "103.59.181.11":
        return False
      return True

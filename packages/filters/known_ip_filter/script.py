CLEAN_IP = {'103.59.181.11', '8.8.8.8'}


def condition(event):
    if event.get('destination_ip') in CLEAN_IP:
        return False
    else:
        return True


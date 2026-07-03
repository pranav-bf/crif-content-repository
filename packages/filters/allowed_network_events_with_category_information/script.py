def condition(event):
    return (
        event.get('event_category_desc') is not None
        or event.get('event_category_id') is not None
        or event.get('event_action') == 'allow'
    ) and event.get('destination_ip') not in {'103.59.181.11', '8.8.8.8'}


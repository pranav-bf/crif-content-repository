DROP_COUNTRIES = {'UNKNOWN', 'RESERVED'}


def condition(event):
    src = (event.get('source_country') or '').upper()
    dst = (event.get('destination_country') or '').upper()
    
    if src in DROP_COUNTRIES or dst in DROP_COUNTRIES:
        return False  
    return True


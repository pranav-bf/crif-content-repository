DROP_COUNTRIES = {'UNKNOWN', 'RESERVED'}
CLEAN_IP = {'103.59.181.11', '8.8.8.8'}


def condition(event):
    dst_ip = event.get('destination_ip')
    if dst_ip:
        dst_ip = str(dst_ip).strip().split(':')[0]

    dst_country = (event.get('destination_country') or '').upper().strip()

    if dst_ip in CLEAN_IP:
        return False

    if dst_country in DROP_COUNTRIES:
        return False

    return True


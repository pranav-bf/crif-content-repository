EXCLUDED_IPS = ["103.59.181.11"]


def condition(event):
    source_ip=event.get("source_ip")
    destination_ip=event.get("destination_ip")
    if not source_ip or not destination_ip:
        return False
    src_external = (source_ip not in EXCLUDED_IPS) and (not is_internal_ip(source_ip))
    dst_external = (destination_ip not in EXCLUDED_IPS) and (not is_internal_ip(destination_ip))
    return src_external or dst_external


def is_internal_ip(ip_str):
    if not ip_str:
        return False

    parts = ip_str.split(".")
    if len(parts) != 4:
        return False

    try:
        a, b, c, d = [int(p) for p in parts]
    except ValueError:
        return False

    # Validate range 0-255
    if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
        return False

    # Private IP ranges
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True

    # Loopback
    if a == 127:
        return True

    # Link-local
    if a == 169 and b == 254:
        return True

    return False
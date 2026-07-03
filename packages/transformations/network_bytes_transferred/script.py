


def transform(event):
    sentbytes = safe_int(event.get("network_bytes_out"))
    receivedbytes = safe_int(event.get("network_bytes_in"))

    event["network_bytes_transferred"] = sentbytes + receivedbytes
    return event


def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
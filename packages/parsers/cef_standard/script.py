def parse(data):
    parts = data.split("|")
    if len(parts) < 7:
        raise ValueError("Invalid CEF format")
    return {
        "version": parts[0].split(":")[-1],
        "device_vendor": parts[1],
        "device_product": parts[2],
        "device_version": parts[3],
        "signature_id": parts[4],
        "name": parts[5],
        "severity": parts[6],
        "extension": "|".join(parts[7:]) if len(parts) > 7 else ""
    }

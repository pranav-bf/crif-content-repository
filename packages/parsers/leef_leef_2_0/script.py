def parse(data):
    lines = data.strip().split('\n')
    header = lines[0]
    if not header.startswith("LEEF:"):
        raise ValueError("Invalid LEEF format")
    parts = header.split("|")
    kv_text = "\n".join(lines[1:])
    kv_pairs = {}
    for kv in kv_text.strip().split('\t'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            kv_pairs[k.strip()] = v.strip()
    return {
        "version": parts[0].split(":")[-1],
        "vendor": parts[1],
        "product": parts[2],
        "version_detail": parts[3],
        "event_id": parts[4],
        "fields": kv_pairs
    }

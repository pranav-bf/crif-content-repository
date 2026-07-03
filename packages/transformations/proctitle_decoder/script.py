

def transform(event):
    try:
        hex_string = event.get('proctitle')
        if not hex_string:
            return event
        raw = hex_string.decode('hex')
        parts = raw.split('\x00')
        decoded_parts = []
        for p in parts:
            if not p:
                continue
            try:
                decoded_parts.append(p.decode('utf-8'))
            except:
                decoded_parts.append(p)  # fallback
        event['decoded_proctitle'] = " ".join(decoded_parts)
    except Exception as e:
        print("Error decoding proctitle: {0}".format(e))
    return event

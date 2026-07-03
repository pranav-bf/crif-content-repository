

def transform(event):
    if "source_ip" in event:
        val = str(event["source_ip"])
        if val != "?":
            if val.startswith("::ffff:"):
                val = val[7:]
            if "." in val:
                parts = val.split(".")
                if len(parts) >= 4:
                    event["source_ip"] = ".".join(parts[:4])

    if "host" in event:
        val = str(event["host"])
        if val != "?":
            if val.startswith("::ffff:"):
                val = val[7:]
            if "." in val:
                parts = val.split(".")
                if len(parts) >= 4:
                    event["host"] = ".".join(parts[:4])

    return event

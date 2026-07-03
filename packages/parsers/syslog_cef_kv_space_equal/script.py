import re


def parse(data):
    event = {}


    syslog = re.match(r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+', data)

    if syslog:
        event["timestamp"] = syslog.group(3)
        event["syslog_hostname"] = syslog.group(4)


    idx = data.find("CEF:")

    if idx == -1:
        raise ValueError("CEF payload not found")

    cef = data[idx:]

    parts = cef.split("|", 7)

    if len(parts) != 8:
        raise ValueError("Invalid CEF format")

    event.update({
        "version": parts[0].split(":")[-1],
        "device_vendor": parts[1].strip(),
        "device_product": parts[2].strip(),
        "device_version": parts[3].strip(),
        "signature_id": parts[4].strip(),
        "name": parts[5].strip(),
        "severity": parts[6].strip()
    })

    extension = parts[7].strip()

    key_pattern = re.compile(r'([A-Za-z0-9_.-]+)=')

    matches = list(key_pattern.finditer(extension))

    for i, match in enumerate(matches):

        key = match.group(1)

        value_start = match.end()

        if i + 1 < len(matches):
            value_end = matches[i + 1].start()
        else:
            value_end = len(extension)

        value = extension[value_start:value_end].strip()

        
        if len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or \
               (value[0] == "'" and value[-1] == "'"):
                value = value[1:-1]

        
        if value == "":
            value = None

        event[key] = value

    return event


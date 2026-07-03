import re
RFC5424_RE = re.compile(r"<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.+)")


def parse(data):
    match = RFC5424_RE.match(data)
    if not match:
        raise ValueError("Invalid RFC 5424 format")
    return {
        "priority": match.group(1),
        "timestamp": match.group(2),
        "hostname": match.group(3),
        "app_name": match.group(4),
        "proc_id": match.group(5),
        "msg_id": match.group(6),
        "structured_data": match.group(7)
    }


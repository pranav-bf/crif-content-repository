import time



def init(event):
  return "initialization completed"


def criteria(meta):
    return meta.get('provider') == 'Linux' and meta.get('group') == 'OS' \
        and meta.get('type') == 'Security'

def drop(event):
  return True


def timestamp(event):
    ts = event.get("date")
    if ts:
        return int(float(ts) * 1000)
    return None


def message(event):
    parsed = dictionary(event)

    details = parsed.get("event_details")
    host = parsed.get("host")
    process = parsed.get("process_name")
    pid = parsed.get("process_id")
    action = parsed.get("event_action")
    ip = parsed.get("source_ip")
    path = parsed.get("process_path")

    parts = []

    if action:
        parts.append("Event %s detected with" % action)
    else: 
        parts.append("Event detected with")

    if ip:
        if (ip != '?'):
            parts.append("on source ip %s using" % ip)
        else:
            parts.append("on host %s using" % host)

    if process:
        if pid:
            parts.append("using process %s and process id %s" % (process, pid))
        else:
            parts.append("process %s on path %s" % (process, path))
    if details:
        parts.append("with details %s" % details)

    return " ".join(parts)

def dictionary(event):
    log_msg = _parse_log(event)
    data = {}

    exe = _extract_value(log_msg, "exe=")
    if exe:
        data["process_path"] = exe
        data["process_name"] = exe.split("/")[-1]

    op = _extract_value(log_msg, "op=")
    if op:
        data["event_action"] = op
    else:
        lower = log_msg.lower()
        if "resumed" in lower:
            data["event_action"] = "resumed"
        elif "suspended" in lower:
            data["event_action"] = "suspended"
        elif "failed" in lower:
            data["event_action"] = "failed"
        elif "started" in lower:
            data["event_action"] = "started"
        elif "stopped" in lower:
            data["event_action"] = "stopped"

    user = _extract_value(log_msg, "acct=")
    if user:
        data["user_name"] = user

    ip = _extract_value(log_msg, "addr=")
    if ip:
        data["source_ip"] = ip

    parts = log_msg.split()
    for p in parts:
        if ":" in p:
            sp = p.split(":")
            if len(sp) == 2:
                ip_part, port = sp
                if ip_part.count(".") == 3 and port.isdigit():
                    data["source_ip"] = ip_part
                    data["source_port"] = port

    host = _extract_value(log_msg, "hostname=")
    if host:
        data["host"] = "unknown" if host == "?" else host
    else:
        parts = log_msg.split()
        if len(parts) > 3:
            data["host"] = parts[3]

    if "[" in log_msg and "]:" in log_msg:
        before = log_msg.split("[")[0].split()
        if before:
            data.setdefault("process_name", before[-1])

        pid = _extract_between(log_msg, "[", "]")
        if pid and pid.isdigit():
            data["process_id"] = str(pid)

    if "]:" in log_msg:
        msg = log_msg.split("]:", 1)[-1]

        if "[v" in msg:
            msg = msg.split("[v")[0]

        if msg.startswith("["):
            msg = msg.split("]", 1)[-1]

        msg = msg.strip().rstrip('}')

        if not msg[:2].isdigit():
            if "event_action" in data:
                data["event_details"] = data["event_action"]
            else:
                data["event_details"] = msg.split(",")[0].strip()

    return data



def _extract_value(log_msg, key):
    idx = log_msg.find(key)
    if idx == -1:
        return None

    start = idx + len(key)
    end = log_msg.find(" ", start)

    if end == -1:
        end = len(log_msg)

    return log_msg[start:end].strip('"')
def _extract_between(text, start_char, end_char):
    start = text.find(start_char)
    end = text.find(end_char, start + 1)

    if start != -1 and end != -1:
        return text[start+1:end]

    return None
def _parse_log(event):
    raw_log = event.get("log", "")

    key = "msg='"
    start = raw_log.find(key)

    if start != -1:
        start += len(key)
        end = raw_log.find("'", start)
        if end != -1:
            msg = raw_log[start:end]
            return msg.replace('\\"', '"').replace('\\/', '/')

    return raw_log.replace('\\/', '/')
import json
import re

ALT_LEGACY_RE = re.compile(r'^<(\d+)>Alteon:$')
DP_RE = re.compile(r'^<(\d+)>DefensePro:$')
ALT_RFC_RE = re.compile(r'^<(\d+)>(\S+)\s+(\S+)\s+(\S+)\s+AlteonOS\s+<([^>]+)>:\s+(.*)$')
TOKEN_RE = re.compile(r'"([^"]*)"|(\S+)')


# =========================
# ENTRY POINT
# =========================
def parse(message):
    raw = unwrap_message(message)

    if not raw:
        return fail("Empty message")

    if "DefensePro:" in raw:
        return parse_defensepro(raw)

    if "AlteonOS" in raw:
        return parse_alteon_rfc(raw)

    if "Alteon:" in raw:
        return parse_alteon_legacy(raw)

    return fallback_parser(raw)


# =========================
# DEFENSEPRO PARSER
# =========================
def parse_defensepro(raw):
    tokens = tokenize(raw)

    if len(tokens) < 4:
        return fail("DefensePro token shortage")

    m = DP_RE.match(tokens[0])
    if not m:
        return fail("Invalid DefensePro header")

    try:
        if len(tokens) > 10 and is_ip(tokens[8]) and is_ip(tokens[10]):
            return parse_defensepro_traffic(tokens, m)
        else:
            return parse_defensepro_system(tokens, m)

    except:
        return fail("DefensePro parse failure")


# =========================
# TRAFFIC LOG
# =========================
def parse_defensepro_traffic(tokens, m):
    length = len(tokens)

    severity = tokens[length - 3] if length >= 3 else None
    action = tokens[length - 2] if length >= 2 else None
    event_id = tokens[length - 1] if length >= 1 else None

    return {
        "success": True,
        "vendor": "Radware",
        "product": "DefensePro",
        "event_type": "traffic",

        "syslog_pri": to_int(m.group(1)),
        "event_time": iso_time(tokens[1], tokens[2]),

        "log_level": tokens[3],
        "event_code": to_int(tokens[4]),
        "category": tokens[5],
        "attack_name": tokens[6],
        "protocol": lower(tokens[7]),

        "src_ip": tokens[8],
        "src_port": to_int(tokens[9]),
        "dst_ip": tokens[10],
        "dst_port": to_int(tokens[11]),

        "policy_id": to_int(tokens[12]),
        "policy_name": tokens[13],
        "interface": tokens[14],
        "state": tokens[15],

        "severity": lower(severity),
        "action": lower(action),
        "event_id": event_id
    }


# =========================
# SYSTEM LOG
# =========================
def parse_defensepro_system(tokens, m):
    return {
        "success": True,
        "vendor": "Radware",
        "product": "DefensePro",
        "event_type": "system",

        "syslog_pri": to_int(m.group(1)),
        "event_time": iso_time(tokens[1], tokens[2]),
        "log_level": tokens[3],

        "message": " ".join(tokens[4:])
    }


# =========================
# ALTEON
# =========================
def parse_alteon_rfc(raw):
    m = ALT_RFC_RE.match(raw)

    if not m:
        return fail("Invalid Alteon RFC format")

    return {
        "success": True,
        "vendor": "Radware",
        "product": "Alteon",

        "syslog_pri": to_int(m.group(1)),
        "event_time": m.group(2),
        "hostname": m.group(3),
        "log_level": m.group(4),
        "module": m.group(5),
        "message": m.group(6)
    }


def parse_alteon_legacy(raw):
    tokens = tokenize(raw)

    if len(tokens) < 4:
        return fail("Alteon legacy token shortage")

    m = ALT_LEGACY_RE.match(tokens[0])
    if not m:
        return fail("Invalid Alteon legacy header")

    code = None
    if len(tokens) > 4 and is_number(tokens[4]):
        code = to_int(tokens[4])
        msg = " ".join(tokens[5:])
    else:
        msg = " ".join(tokens[4:])

    return {
        "success": True,
        "vendor": "Radware",
        "product": "Alteon",

        "syslog_pri": to_int(m.group(1)),
        "event_time": iso_time(tokens[1], tokens[2]),
        "log_level": tokens[3],
        "event_code": code,
        "message": msg
    }


# =========================
# FALLBACK
# =========================
def fallback_parser(raw):
    return {
        "success": True,
        "vendor": "Radware",
        "product": "Unknown",
        "event_type": "unknown",
        "message": raw
    }


# =========================
# HELPERS
# =========================
def unwrap_message(message):
    if not message:
        return ""

    if isinstance(message, dict):
        return message.get("log", "").strip()

    try:
        raw = message.strip()
    except:
        raw = str(message)

    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and "log" in obj:
            return obj["log"].strip()
    except:
        pass

    return raw


def tokenize(s):
    result = []
    for a, b in TOKEN_RE.findall(s):
        if a:
            result.append(a)
        else:
            result.append(b)
    return result


def iso_time(d, t):
    try:
        p = d.split("-")
        return p[2] + "-" + p[1] + "-" + p[0] + "T" + t
    except:
        return None


def to_int(v):
    try:
        return int(v)
    except:
        return None


def lower(v):
    try:
        return v.lower()
    except:
        return v


def is_number(v):
    try:
        int(v)
        return True
    except:
        return False


def is_ip(v):
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', v))


def fail(msg):
    return {"success": False, "error": msg}
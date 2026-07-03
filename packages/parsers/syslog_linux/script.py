import json
import re

SYSLOG_REGEX = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<program>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

AUDIT_MAIN_REGEX = re.compile(
    r'type=(?P<type>\w+)\s+msg=audit\((?P<timestamp>\d+\.\d+):(?P<seq>\d+)\):\s+(?P<rest>.*)'
)

KV_REGEX = re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')



# -----------------------------
# Parsers
# -----------------------------
def parse_syslog(line):
    match = SYSLOG_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    return data
    
def parse_audit(line):
    match = AUDIT_MAIN_REGEX.search(line)
    if not match:
        return None

    data = match.groupdict()

    rest = data.pop("rest", "")

    # -----------------------------
    # Step 1: Extract msg='...'
    # -----------------------------
    msg_match = re.search(r"msg='(.*?)'", rest)
    inner_msg = None

    if msg_match:
        inner_msg = msg_match.group(1)
        rest = rest.replace(msg_match.group(0), "")  # remove msg block

    # -----------------------------
    # Step 2: Parse remaining KV
    # -----------------------------
    for key, value in KV_REGEX.findall(rest):
        clean = clean_value(value)
        data[key] = clean

    # -----------------------------
    # Step 3: Parse inner msg KV
    # -----------------------------
    if inner_msg:
        inner_kv = {}
        for key, value in KV_REGEX.findall(inner_msg):
            clean = clean_value(value)
            inner_kv[key] = clean

        data["msg_data"] = inner_kv

    return data


# -----------------------------
# JSON Fixer
# -----------------------------
def fix_inner_json(log_str):
    # Remove control char
    log_str = log_str.replace('\\u001D', ' ')

    # Fix: ensure "msg": VALUE → "msg": "VALUE"
    key = '"msg":'
    idx = log_str.find(key)

    if idx == -1:
        return log_str

    start = idx + len(key)

    # If already quoted → skip
    if start < len(log_str) and log_str[start] == '"':
        return log_str

    # Find where msg ends → before last }
    end = log_str.rfind('}')
    if end <= start:
        return log_str

    msg_value = log_str[start:end].strip()

    # Escape properly
    msg_value = msg_value.replace('\\', '\\\\').replace('"', '\\"')

    fixed = log_str[:start] + "\"" + msg_value + "\"" + log_str[end:]
    return fixed


# -----------------------------
# Helpers
# -----------------------------
def try_parse_line(line, log_type):
    
    if log_type == 'auditd_log':
        return parse_audit(line)
    else:
        return parse_syslog(line) #message or secure


def safe_json_loads(data):
    try:
        return json.loads(data)
    except ValueError:
        return None

def clean_value(value):
    value = value.replace('\\/', '/')   # fix \/ → /
    value = value.replace('\\"', '"')   # fix \" → "
    value = value.replace('\\\\', '\\') # fix \\ → \

    value = value.strip('"\'').strip()
    return value

# -----------------------------
# Main Parser
# -----------------------------
def parse(data):
    parsed_data = safe_json_loads(data)

    if not parsed_data:    
        raise ValueError("Invalid JSON data: {}".format(data))

    log_str = parsed_data.get("log")
    
    # Parse inner JSON if possible
    if isinstance(log_str, (str, unicode)):
        inner = safe_json_loads(log_str)

        if not inner:

            fixed = fix_inner_json(log_str)

            inner = safe_json_loads(fixed)


            if not inner:
                raise ValueError("Invalid inner JSON: {}".format(fixed))

        parsed_data["log"] = inner
    
    source = parsed_data["log"].get('source')
    # Extract actual message
    line = parsed_data["log"].get("msg", "")
  
    parsed_line = try_parse_line(line, source)
    
    parsed_data["log"]["msg"] = parsed_line
    parsed_data["log"]["jumpserver"] = parsed_data.get("jumpserver")

    return parsed_data.get("log")
    # parsed_data = safe_json_loads(data)
    
    # # Case 1: Not JSON → raw log
    # if not parsed_data:
    #     return try_parse_line(data)

    # # Case 2: FluentBit JSON wrapper
    # if parsed_data.pop("format",None) != "json_lines_fb":
    #     return try_parse_line(data)
    
    # log_str = parsed_data.get("log")
    
    # # Parse inner JSON if possible
    # if isinstance(log_str, (str, unicode)):
    #     inner = safe_json_loads(log_str)

    #     if not inner:

    #         fixed = fix_inner_json(log_str)

    #         inner = safe_json_loads(fixed)


    #         if not inner:

    #             raise ValueError("Invalid inner JSON: {}".format(fixed))

    #     parsed_data["log"] = inner
    
    # source = parsed_data["log"].get('source')
    # # Extract actual message
    # line = parsed_data["log"].get("msg", "")
  
    # parsed_line = try_parse_line(line, source)
    
    # parsed_data["log"]["msg"] = parsed_line
    # parsed_data["log"]["jumpserver"] = parsed_data.get("jumpserver")

    # return parsed_data.get("log")

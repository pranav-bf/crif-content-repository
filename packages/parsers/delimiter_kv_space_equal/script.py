import re
import json
INT_FIELDS = {
    "eventtime",
    "srcport",
    "dstport",
    "sessionid",
    "proto",
    "policyid",
    "duration",
    "sentbyte",
    "rcvdbyte",
    "sentpkt",
    "rcvdpkt",
    "dstserver",
}

def parse(data):
    if not data:
        return {}

    if data[0] == "{":
        try:
            obj = json.loads(data)
            if obj.get("format") == "json_lines_fb":
                result = parse_kv_fast(obj.get("log", ""))
                result["jumpserver"] = obj.get("jumpserver")
                return result
        except ValueError:
            pass

    return parse_kv_fast(data)


def parse_kv_fast(data):
    if not data:
        return {}

    length = len(data)
    i = 0

    # Remove leading syslog PRI like <189>
    if data[0] == "<":
        end = data.find(">")
        if end > 0:
            i = end + 1
            while i < length and data[i] == " ":
                i += 1

    parsed = {}

    while i < length:
        # Skip spaces
        while i < length and data[i] == " ":
            i += 1

        if i >= length:
            break

        key_start = i

        # Read key until =
        while i < length and data[i] != "=":
            i += 1

        if i >= length:
            break

        key = data[key_start:i]
        i += 1  # skip =

        if i >= length:
            parsed[key] = ""
            break

        # Quoted value
        if data[i] == '"':
            i += 1
            val_start = i

            while i < length and data[i] != '"':
                i += 1

            parsed[key] = data[val_start:i]

            if i < length:
                i += 1  # skip closing quote

        # Unquoted value
        else:
            val_start = i

            while i < length and data[i] != " ":
                i += 1

            parsed[key] = data[val_start:i]

    return convert_selected(parsed)


def convert_selected(parsed):
    for field in INT_FIELDS:
        val = parsed.get(field)
        if val and val.isdigit():
            parsed[field] = int(val)

    return parsed

# import re
# import json
# KV_PATTERN = re.compile(r'(\w+)=("[^"]*"|\S+)')


# def parse(data):
#     if not data:

#         return {}

#     # Fast JSON check before json.loads()

#     if data[0] == '{':

#         try:

#             obj = json.loads(data)

#             if obj.get("format") == "json_lines_fb":

#                 result = parse_kv(obj.get("log", ""))

#                 result["jumpserver"] = obj.get("jumpserver")

#                 return result

#         except Exception:

#             pass

#     return parse_kv(data)


# def parse_kv(data):
#     if not data:

#         return {}

#     # Fast PRI removal without regex

#     if data[0] == '<':

#         pos = data.find('>')

#         if pos > 0:

#             data = data[pos + 1:].lstrip()

#     parsed = {}

#     for match in KV_PATTERN.finditer(data):  # avoids findall list creation

#         key = match.group(1)

#         val = match.group(2)

#         if val and val[0] == '"' and val[-1] == '"':

#             val = val[1:-1]

#         parsed[key] = convert_value(val)

#     return parsed
# def convert_value(val):
#     if not val:

#         return val

#     if val == "true":

#         return True

#     if val == "false":

#         return False

#     # Avoid exceptions

#     if val.isdigit():

#         return int(val)

#     if '.' in val:

#         try:

#             return float(val)

#         except ValueError:

#             pass

#     return val
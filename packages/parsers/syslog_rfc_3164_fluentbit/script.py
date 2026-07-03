import json as jsonparser
import re as re3164
# import csv

def parse(data):
    try:
        json_data = jsonparser.loads(data)
        if json_data and json_data.get("format") == "json_lines_fb":
          return parse_rfc(json_data.get("log"))
    except ValueError:
        raise ValueError("Invalid JSON format")


def parse_rfc(data):
    match = re3164.match(r"<(\d+)>(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) ([\w.-]+) (.*)", data)
    if not match:
        raise ValueError("Invalid RFC 3164 format")
    return {
        "priority": match.group(1),
        "timestamp": match.group(2),
        "host": match.group(3),
        "message": match.group(4)
    }

# def _parse_fields(raw_log):
#     if not raw_log:
#         return []
#     try:
#         return next(csv.reader([raw_log]))
#     except:
#         return []
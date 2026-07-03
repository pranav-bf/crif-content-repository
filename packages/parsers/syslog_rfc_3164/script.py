import re
import json
import csv
RFC3164_RE = re.compile(r"^<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>[\w.-]+) (?P<message>.*)$")


def parse(data):
    try:
        json_data = json.loads(data)
        if json_data and json_data.get("format") == "json_lines_fb":
          return parse_rfc(json_data.get("log"), True, json_data.get("jumpserver"))
    except ValueError:
        return parse_rfc(data, False, "")


def _parse_fields(raw_log):
    if not raw_log:
        return []
    try:
        return next(csv.reader([raw_log]))
    except:
        return []
def parse_rfc(data, parse_csv, jumpserver):
    match = RFC3164_RE.match(data)
    if not match:
        raise ValueError("Invalid RFC 3164 format")

    if parse_csv:
      return {
          "priority": match.group(1),
          "timestamp": match.group(2),
          "host": match.group(3),
          "message": _parse_fields(match.group(4)),
          "jumpserver": jumpserver
      }
    else:
      return {
        "priority": match.group(1),
        "timestamp": match.group(2),
        "host": match.group(3),
        "message": match.group(4),
        "jumpserver": jumpserver
    }
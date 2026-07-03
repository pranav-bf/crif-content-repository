import json


def parse(data):
    try:
        json_data = json.loads(data)
        if json_data and json_data.get("format") == "json_lines_fb":
          parsed = json.loads(json_data.get("log"))
          parsed["jumpserver"] = json_data.get("jumpserver")
          return parsed
        else:
          return json_data                          
    except Exception as e:
        raise ValueError(
            "Invalid JSON format: %s | Event: %s" % (str(e), str(data))
        )


import json as jsonstix

def parse_stix(data):
    try:
        parsed = jsonstix.loads(data)
    except ValueError:
        raise ValueError("Invalid STIX 2.1 JSON format")
    if parsed.get("type") != "bundle":
        raise ValueError("Expected a STIX bundle")
    return parsed

import re as re103

def parse(data):
    result = {}
    try:
        fields = re103.findall(r':(\d+[A-Z]?):(.*?)\r?\n(?=:|\Z)', data, re103.DOTALL)
        for k, v in fields:
            result[k] = v.strip()
    except Exception:
        raise ValueError("Invalid SWIFT MT103 format")
    return result

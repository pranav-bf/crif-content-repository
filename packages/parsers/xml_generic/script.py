import xml.etree.ElementTree as ET1

def parse(data):
    try:
        root = ET1.fromstring(data)
    except ET1.ParseError:
        raise ValueError("Invalid XML format")
    result = {}
    for child in root:
        result[child.tag] = child.text
    return {root.tag: result}

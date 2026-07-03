import xml.etree.ElementTree as ET2

def parse(data):
    try:
        root = ET2.fromstring(data)
    except ET2.ParseError:
        raise ValueError("Invalid ISO 20022 pain.001 XML format")
    result = {}
    for child in root:
        result[child.tag] = child.text
    return {root.tag: result}

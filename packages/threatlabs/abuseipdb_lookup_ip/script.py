ACTION_ID = "threatintel.abuseipdb.lookup_ip"

def name():
    return ACTION_ID

def variables():
    return ti.resolve(ACTION_ID + ".variables") if ti is not None else {}


def inputschema():
    return ti.resolve(ACTION_ID + ".inputschema") if ti is not None else {"type": "object", "properties": {}}


def outputschema():
    return ti.resolve(ACTION_ID + ".outputschema") if ti is not None else {"type": "object", "properties": {}}


def execute(input):
    if ti is None:
        return {"success": False, "message": "Missing implicit variable: ti", "action": ACTION_ID}
    if input is None:
        input = {}
    return ti.call(ACTION_ID).execute(input)


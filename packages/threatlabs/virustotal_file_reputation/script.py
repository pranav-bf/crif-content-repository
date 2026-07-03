ACTION_ID = "threatintel.virustotal.file_reputation"

def criteria(artefactvalue):
    return True

def analytics(artefactvalue):
    return {
            "success": True,
            "message": "Action executed successfully"
        }

def expiry():
    return 3600

def weight():
    return 1.0

def execute(input):
    if ti is None:
        return {"success": False, "message": "Missing implicit variable: ti", "action": ACTION_ID}
    if input is None:
        input = {}
    return ti.call(ACTION_ID).execute(input)
def inputschema():
    return ti.resolve(ACTION_ID + ".inputschema") if ti is not None else {"type": "object", "properties": {}}
def variables():
    return ti.resolve(ACTION_ID + ".variables") if ti is not None else {}
def outputschema():
    return ti.resolve(ACTION_ID + ".outputschema") if ti is not None else {"type": "object", "properties": {}}
def name():
    return ACTION_ID
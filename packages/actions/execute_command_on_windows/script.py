ACTION_ID = "windows.run_command"


def name():
    return ACTION_ID
  
def variables():
    return action.resolve(ACTION_ID + ".variables") if action is not None else {}


def inputschema():
    return action.resolve(ACTION_ID + ".inputschema") if action is not None else {"type": "object", "properties": {}}


def outputschema():
    return action.resolve(ACTION_ID + ".outputschema") if action is not None else {"type": "object", "properties": {}}


def category():
    return action.resolve(ACTION_ID + ".category") if action is not None else "UTILITY"


def execute(input):
    if action is None:
        return {"success": False, "message": "Missing implicit variable: action", "action": ACTION_ID}
    if input is None:
        input = {}
    return action.call(ACTION_ID).execute(input)


def output(executionResult):
    return executionResult


def callback(payload, context):
    if action is None:
        return {"processed": False, "message": "Missing implicit variable: action", "action": ACTION_ID}
    if payload is None:
        payload = {}
    if context is None:
        context = {}
    return action.call(ACTION_ID).callback(payload, context)


def callbackinputschema():
    return action.resolve(ACTION_ID + ".callbackinputschema") if action is not None else {"type": "object", "properties": {}}


def callbackoutputschema():
    return action.resolve(ACTION_ID + ".callbackoutputschema") if action is not None else {"type": "object", "properties": {}}

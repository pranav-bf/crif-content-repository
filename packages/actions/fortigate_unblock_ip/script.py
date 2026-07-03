ACTION_ID = "fortigate.unblock_ip"

def name():
    
    return ACTION_ID




def execute(input):
    if action is None:
        return {"success": False, "message": "Missing implicit variable: action", "action": ACTION_ID}
    if input is None:
        input = {}
    return action.call(ACTION_ID).execute(input)

def category():

    return None



def inputschema():
    return action.resolve(ACTION_ID + ".inputschema") if action is not None else {"type": "object", "properties": {}}

def outputschema():
    return action.resolve(ACTION_ID + ".outputschema") if action is not None else {"type": "object", "properties": {}}

def callback(data):

    return None



def callbackinputschema():

    return None

def callbackoutputschema():

    return None

def variables():
    return action.resolve(ACTION_ID + ".variables") if action is not None else {}
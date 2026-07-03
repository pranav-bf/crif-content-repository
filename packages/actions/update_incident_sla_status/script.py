def name():
    """
    Returns the unique action name.

    Returns:
        str: Unique identifier for this action.
    """
    # TODO: Define unique action name
    return "update-incident-sla-status"




def execute(input):
    id = input.get("id")
    payload = {
        "identifier": id
    }

    return incidentService.updateIncidentResponseSLA(payload)




def category():
    """
    Returns the action category.

    Returns:
        str: Category grouping for this action.
    """
    # TODO: Define action category
    # Common categories: "Network Security", "Endpoint Security", "Threat Intelligence", 
    # "Incident Response", "Compliance", "Monitoring", "Automation"
    return "General"




def inputschema():
    """
    Returns the expected input schema.

    Returns:
        dict: JSON schema defining expected input parameters.
    """
    # TODO: Define input schema for action parameters
    return {
        "type": "object",
        "required": ["id"],
        "properties": {
            "id": {
                "type": "string",
                "description": "Unique Identifier of an incident"
            }
        }
    }
















def outputschema():
    return {
        "type": "object",
        "properties": {
            "updated": {
                "type": "boolean",
                "description": "Whether the status has been updated successfully"
            },
            "message": {
                "type": "string",
                "description": "Human-readable result message"
            },
            "status": {
                "type": "string",
                "description": "Detection status used while updating"
            },
            "error": {
                "type": "string",
                "description": "Error message if action failed"
            }
        }
    }










def callback(data):
    """
    Handles callbacks from external systems.

    Args:
        payload (dict): The callback payload from external app.
        context (dict): Original context including appId, app, customer, tenant.

    Returns:
        dict: Dict containing callback processing result.
    """
    # TODO: Implement callback handling logic
    # Example:
    # callback_type = payload.get("type")
    # if callback_type == "status_update":
    #     status = payload.get("status")
    #     # Update action status in database
    #     return {"processed": True, "status": status}
    # else:
    #     return {"processed": False, "message": "Unknown callback type"}
    
    return {
        "processed": True,
        "message": "Callback processed successfully"
    }
















def callbackinputschema():
    """
    Returns expected callback input schema.

    Returns:
        dict: JSON schema defining expected callback payload structure.
    """
    # TODO: Define callback input schema
    return {
        "type": "object",
        "required": ["type", "actionId"],
        "properties": {
            "type": {
                "type": "string",
                "description": "Type of callback (e.g., status_update, completion)"
            },
            "actionId": {
                "type": "string",
                "description": "Original action identifier"
            },
            "status": {
                "type": "string",
                "enum": ["pending", "in_progress", "completed", "failed"],
                "description": "Current status of the action"
            },
            "result": {
                "type": "object",
                "description": "Result data from the external system"
            },
            "error": {
                "type": "string",
                "description": "Error information if action failed"
            },
            "timestamp": {
                "type": "integer",
                "description": "Callback timestamp in epoch milliseconds"
            }
        }
    }
















def callbackoutputschema():
    """
    Returns expected callback output schema.

    Returns:
        dict: JSON schema defining expected callback response structure.
    """
    # TODO: Define callback output schema
    return {
        "type": "object",
        "properties": {
            "processed": {
                "type": "boolean",
                "description": "Whether the callback was processed successfully"
            },
            "message": {
                "type": "string",
                "description": "Processing result message"
            },
            "status": {
                "type": "string",
                "description": "Updated status after callback processing"
            },
            "details": {
                "type": "object",
                "description": "Additional processing details"
            },
            "error": {
                "type": "string",
                "description": "Error message if callback processing failed"
            }
        }
    }

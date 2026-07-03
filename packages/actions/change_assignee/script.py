def name():
    """
    Returns the unique action name.

    Returns:
        str: Unique identifier for this action.
    """
    # TODO: Define unique action name
    return "asignee_change"












def execute(input):
    """
    Main execution function for the action.

    Args:
        input (dict): Dict containing action parameters.

    Returns:
        dict: Dict containing action result.
    """
    # TODO: Implement main action logic
    # Example implementation:
    # ip = input.get("ip")
    # duration = input.get("duration", 3600)
    # try:
    #     # Perform the action (e.g., API call, system command)
    #     result = block_ip_address(ip, duration)
    #     return {
    #         "success": True,
    #         "message": f"Successfully blocked IP {ip} for {duration} seconds",
    #         "blockId": result.get("id"),
    #         "details": result
    #     }
    # except Exception as e:
    #     return {
    #         "success": False,
    #         "message": f"Failed to block IP: {str(e)}",
    #         "error": str(e)
    #     }
    asignee = input.get("asignee")
    asigneetype = input.get("asigneetype")
    incidentid = input.get("incidentid")
    payload = {
        "asignee": asignee,
        "asigneetype":asigneetype,
        "identifier": incidentid
    }
    return incidentService.updateIncident(payload)













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
        "required": ["incidentid","asignee"],
        "properties": {
            "incidentid": {
                "type": "string",
                "description": "Unique Identifier of incident to be updated"
            },
            "asigneetype": {
                "type": "string",
                "enum": ["user", "group"],
                "description": "Asignee type for the incident"
            },
            "asignee": {
                "type": "string",
                "description": "Asignee for the incident"
            }
        }
    }












def outputschema():
    """
    Returns the expected output schema.

    Returns:
        dict: JSON schema defining expected output structure.
    """
    # TODO: Define output schema for action results
    return {
        "type": "object",
        "properties": {
            "success": {
                "type": "boolean",
                "description": "Whether the action executed successfully"
            },
            "message": {
                "type": "string",
                "description": "Human-readable result message"
            },
            "actionId": {
                "type": "string",
                "description": "Unique identifier for this action execution"
            },
            "details": {
                "type": "object",
                "description": "Additional details about the action result"
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

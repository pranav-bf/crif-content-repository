# -*- coding: utf-8 -*-
import json
from java.net import URL, HttpURLConnection
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader


def name():
    return "Send Email"



def variables():
    return {
        "type": "object",
        "properties": {
            "sendemail.endpoint": {
                "type": "string",
                "name": "Endpoint",
                "description": "API to trigger email service",
                "secret": False,
                "encrypted": False
            }
        }
    }


def execute(input):
    to = input.get("to")
    subject = input.get("subject")
    template = input.get("template", "")
    content_type = input.get("content_type", "text/plain")

    if not to:
        return {
            "success": False,
            "message": "Missing required field: to",
            "error": "ValidationError"
        }

    if not subject:
        return {
            "success": False,
            "message": "Missing required field: subject",
            "error": "ValidationError"
        }

    try:
        _vars = input_variables
    except NameError:
        _vars = {}

    email_service_url = _vars.get("sendemail.endpoint")
    if not email_service_url:
        return {
            "success": False,
            "message": "Missing configured variable: sendemail.endpoint",
            "error": "ConfigurationError"
        }

    print("Send Email action: using endpoint =" + email_service_url)

    payload = {
        "to": to,
        "subject": subject,
        "msg": template,
        "contentType": content_type
    }

    conn = None
    try:
        body = json.dumps(payload)

        url = URL(email_service_url)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setDoOutput(True)
        conn.setConnectTimeout(15000)
        conn.setReadTimeout(15000)
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json")

        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(body)
        writer.flush()
        writer.close()

        status_code = conn.getResponseCode()
        content_type_header = conn.getHeaderField("Content-Type") or ""

        stream = None
        if status_code >= 200 and status_code < 300:
            stream = conn.getInputStream()
        else:
            stream = conn.getErrorStream()

        resp_body = ""
        if stream is not None:
            reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
            lines = []
            line = reader.readLine()
            while line is not None:
                lines.append(line)
                line = reader.readLine()
            reader.close()
            resp_body = "\n".join(lines)

        details = {}
        if "application/json" in content_type_header.lower() and resp_body:
            try:
                details = json.loads(resp_body)
            except Exception:
                details = {"raw": resp_body}
        elif resp_body:
            details = {"raw": resp_body}

        if status_code < 200 or status_code >= 300:
            return {
                "success": False,
                "message": "Email service returned non-success response",
                "statusCode": status_code,
                "details": details,
                "error": resp_body
            }

        return {
            "success": True,
            "message": "Email request sent to system-email-service for {0}".format(to),
            "statusCode": status_code,
            "details": details
        }

    except Exception as e:
        return {
            "success": False,
            "message": "Unexpected error while sending email",
            "error": str(e)
        }


def output(output_result):
    return {
        "response": output_result,
        "success": output_result.get("success", False),
        "message": output_result.get("message", "Email action executed")
    }


def category():
    return "Notify"


def inputschema():
    return {
        "type": "object",
        "required": ["to", "subject"],
        "properties": {
            "to": {
                "type": "string",
                "description": "Target email address"
            },
            "subject": {
                "type": "string",
                "description": "subject for email"
            },
            "template": {
                "type": "string",
                "description": "Email body (plain text or HTML depending on content_type)",
                "format": "html"
            },
            "content_type": {
                "type": "string",
                "enum": ["text/plain", "text/html"],
                "default": "text/plain",
                "description": "MIME type for body"
            }
        }
    }


def outputschema():
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
            "statusCode": {
                "type": "integer",
                "description": "HTTP status code returned by the email service"
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


def callback(payload, context):
    return {
        "processed": True,
        "message": "Callback processed successfully"
    }


def callbackinputschema():
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
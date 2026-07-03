# function to get the initial status of incident
def start():
    return "Open"

# function to know steps after current status
def workflow():
    return {
        "Open": [
            "Notified"
        ],
        "True Positive": [
            "Close"
        ],
        "Notified": [
            "Response Initiated"
        ],
        "False Positive": [
            "Close"
        ],
        "In Progress": [
            "True Positive",
            "False Positive",
            "Anomolous Safe",
            "Duplicate",
            "False Positive and Suppress",
            "Remediative Action Taken"
        ],
        "Anomolous Safe": [
            "Close"
        ],
        "Duplicate": [
            "Close"
        ],
        "Response Initiated": [
            "In Progress"
        ],
        "False Positive and Suppress": [
            "Mark False Positive"
        ],
        "Mark False Positive": [
            "Close"
        ],
        "Remediative Action Taken": [
            "Close"
        ]
    }

# function to know when the incident is completed
def end():
    return "Close"

# default incident criticality (LOW, MEDIUM, HIGH, CRITICAL)
def criticality():
    return "MEDIUM"

# assignee target type: user or group
def asigneetype():
    return "group"

# default assignee (username or group name)
def assignee():
    return "MSSP_GROUP_SOC_ANALYST"

# function to manage workflow actions
def config():
    return {
        "Open": {
            "automated": True
        },
        "True Positive": {
            "automated": False
        },
        "Notified": {
            "automated": True,
            "action": {
                "name": "send_email",
                "parameters": {
                    "template": "<!DOCTYPE html>\n<html lang=\"en\">\n\n<head>\n    <meta charset=\"UTF-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n    <title>Detection Notification</title>\n    <style>\n        @font-face {\n            font-family: 'Lato';\n            font-style: normal;\n            font-weight: 400;\n            src: local('Lato Regular'), local('Lato-Regular'),\n                url('https://fonts.gstatic.com/s/lato/v23/S6uyw4BMUTPHjxAwXiWtFCc.woff2') format('woff2');\n        }\n\n        body {\n            margin: 0;\n            padding: 0;\n            background-color: #f4f6f8;\n            font-family: 'Lato', 'Segoe UI', sans-serif;\n        }\n\n        img {\n            display: block;\n            max-width: 100%;\n            height: auto;\n        }\n\n        table {\n            border-spacing: 0;\n            border-collapse: collapse;\n        }\n\n        @media only screen and (max-width: 620px) {\n            .wrapper {\n                width: 100% !important;\n                padding: 0 10px !important;\n            }\n\n            .inner-padding {\n                padding: 20px 15px !important;\n            }\n\n            .column {\n                display: block;\n                width: auto !important;\n                margin-bottom: 5px;\n            }\n\n            .cta-button {\n                display: block;\n                width: 100% !important;\n                text-align: center !important;\n                padding: 12px 0 !important;\n            }\n        }\n    </style>\n</head>\n\n<body>\n\n    <table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"padding: 40px 0; margin-top: 20px;\">\n        <tr>\n            <td align=\"center\">\n                <table class=\"wrapper\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\"\n                    style=\"background-color: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 0 8px rgba(0, 0, 0, 0.05);\">\n\n                    <!-- Header -->\n                    <tr>\n                        <td\n                            style=\"background: linear-gradient(117.87deg, #090B19 42.87%, #102A47 99.67%); color: #ffffff; text-align: center; padding: 30px 20px;\">\n                            <img src=\"https://binaryflux.ai/images/logo.png\" alt=\"Binaryflux Logo\"\n                                style=\"height: 35px; margin: auto;\">\n                            <h2 style=\"margin: 10px 0 0;\">Detection Alert</h2>\n                            <p style=\"margin: 8px 0 0;\">Immediate attention required for flagged detection</p>\n                        </td>\n                    </tr>\n\n                    <!-- Highlighted Info Section -->\n                    <tr>\n                        <td class=\"inner-padding\" style=\"padding: 24px;\">\n                            <table width=\"100%\" style=\"font-size: 14px;\">\n                                <tr>\n                                    <td class=\"column\"\n                                        style=\"width: 25%; padding: 10px; background-color: #f9fafb; border: 1px solid #e2e8f0; border-radius: 6px;\">\n                                        <strong>Date:</strong><br>${detection.date}\n                                    </td>\n                                    <td class=\"column\"\n                                        style=\"width: 25%; padding: 10px; background-color: #f9fafb; border: 1px solid #e2e8f0; border-radius: 6px;\">\n                                        <strong>Score:</strong><br>${detection.score}\n                                    </td>\n                                    <td class=\"column\"\n                                        style=\"width: 25%; padding: 10px; background-color: #f9fafb; border: 1px solid #e2e8f0; border-radius: 6px;\">\n                                        <strong>Severity:</strong><br>\n                                        <span style=\"color: #d93025;\">${ detection.severity }</span>\n                                    </td>\n                                    <td class=\"column\"\n                                        style=\"width: 25%; padding: 10px; background-color: #f9fafb; border: 1px solid #e2e8f0; border-radius: 6px;\">\n                                        <strong>Provider:</strong><br>${ detection.provider }\n                                    </td>\n                                </tr>\n                            </table>\n                        </td>\n                    </tr>\n\n                    <!-- Summary Box -->\n                    <tr>\n                        <td class=\"inner-padding\" style=\"padding: 0 24px 20px;\">\n                            <div\n                                style=\"padding: 20px; background-color: #fffbe6; border-left: 4px solid #fbbc04; border-radius: 6px;\">\n                                <strong>Detection Summary:</strong><br>\n                                <p style=\"margin: 8px 0 0; line-height: 1.5;\">${ detection.summary }</p>\n                            </div>\n                        </td>\n                    </tr>\n\n                    <!-- Details Table -->\n                    <tr>\n                        <td class=\"inner-padding\" style=\"padding: 0 24px 30px;\">\n                            <h3\n                                style=\"font-size: 16px; margin-bottom: 12px; border-bottom: 1px solid #eaeaea; padding-bottom: 6px;\">\n                                Detection Details</h3>\n                            <table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n                                <tr>\n                                    <td style=\"padding: 6px 0; width: 35%; vertical-align: top;\"><strong>Detection\n                                            Name:</strong></td>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\">${ detection.detection_name }</td>\n                                </tr>\n                                <tr>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\"><strong>Stream Name:</strong></td>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\">${ detection.stream_name }</td>\n                                </tr>\n                                <tr>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\"><strong>Tenant:</strong></td>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\">${ detection.tenant }</td>\n                                </tr>\n                                <tr>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\"><strong>Entity Type:</strong></td>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\">${ detection.entity_type }</td>\n                                </tr>\n                                <tr>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\"><strong>Entity:</strong></td>\n                                    <td style=\"padding: 6px 0; vertical-align: top;\">${ detection.entity }</td>\n                                </tr>\n                            </table>\n                        </td>\n                    </tr>\n\n                    <!-- CTA -->\n                    <tr>\n                        <td align=\"center\" style=\"padding: 10px 24px 30px;\">\n                            <a class=\"cta-button\" href=\"${(appurl)!}\"\n                                style=\"background-color: #1a73e8; color: #ffffff; padding: 12px 28px; font-size: 15px; border-radius: 6px; text-decoration: none;\">\n                                Login\n                            </a>\n                        </td>\n                    </tr>\n\n                    <!-- Footer -->\n                    <tr>\n                        <td align=\"center\"\n                            style=\"background-color: #f5f7fa; color: #6a737d; font-size: 12px; padding: 20px;\">\n                            &copy; ${detection.date?datetime(\"EEE MMM dd HH:mm:ss z yyyy\")?string(\"yyyy\")} Binaryflux. All rights reserved.<br>\n                            <span style=\"font-size: 11px;\">This is an automated message. Please do not reply.</span>\n                        </td>\n                    </tr>\n\n                </table>\n            </td>\n        </tr>\n    </table>\n\n</body>\n\n</html>",
                    "subject": "Action Required",
                    "content_type": "text/html",
                    "to": "cybershield@protivitiglobal.in"
                }
            }
        },
        "Close": {
            "automated": True
        },
        "False Positive": {
            "automated": False,
            "action": {
                "name": "update_detection_status",
                "parameters": {
                    "status": "RCA_IGNORE",
                    "id": "$.instanceid"
                }
            }
        },
        "In Progress": {
            "automated": False,
            "description": "Start Investigation"
        },
        "Anomolous Safe": {
            "automated": False,
            "action": {
                "name": "update_detection_status",
                "parameters": {
                    "status": "RCA_IGNORE",
                    "id": "$.instanceid"
                }
            }
        },
        "Duplicate": {
            "automated": False,
            "action": {
                "name": "update_detection_status",
                "parameters": {
                    "id": "$.instanceid",
                    "status": "RCA_IGNORE"
                }
            }
        },
        "Response Initiated": {
            "automated": True,
            "description": "assignment is done to given team",
            "action": {
                "name": "update_incident_sla_status",
                "parameters": {
                    "id": "$.incidentid"
                }
            }
        },
        "False Positive and Suppress": {
            "automated": False,
            "description": "This will mark the incident as false positive and suppress further matching incidents for 30 days",
            "action": {
                "name": "suppress_false_positive_detection",
                "parameters": {
                    "suppressfordays": 30,
                    "incidentid": "$.incidentid"
                }
            }
        },
        "Mark False Positive": {
            "automated": True,
            "description": "Mark false positive",
            "action": {
                "name": "update_detection_status",
                "parameters": {
                    "id": "$.instanceid",
                    "status": "RCA_IGNORE"
                }
            }
        },
        "Remediative Action Taken": {
            "automated": False,
            "description": "A remediative action such as quarantine is already taken on this",
            "action": {
                "name": "update_detection_status",
                "parameters": {
                    "status": "RCA_IGNORE",
                    "id": "$.instanceid"
                }
            }
        }
    }

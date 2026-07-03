from datetime import datetime

def format():
    return "detailCard"




# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": "select * from implicit_algorithm",
        "parameters": {}
    }
  
def algorithm():
    starttime = parameters.get("starttime")
    endtime = parameters.get("endtime")
  
    return investigationDetails.getIncidentDetails(starttime,endtime)



def render(results):

    def safe(value):
        if value is None:
            return u"N/A"
        return unicode(value)

    def safe_rca(value):
        try:
            u_value = unicode(value or u"").strip()
            if not u_value:
                return u"Root Cause Analysis not available for this incident."
            return u_value
        except:
            return u"Root Cause Analysis not available for this incident."

    incidents = {}

    for item in results:

        inc = item.get("incident", {}) or {}
        conclusion = item.get("conclusion", "")

        incident_id = safe(inc.get("id"))
        title = safe(inc.get("name"))
        description = safe(inc.get("description"))
        criticality = safe(inc.get("criticality")).upper()
        status = safe(inc.get("status")).upper()
        assignee = safe(inc.get("assignee"))
        assign_type = safe(inc.get("asigneetype"))

        created_raw = inc.get("createdon")

        if created_raw:
            created_date = datetime.fromtimestamp(
                int(created_raw) / 1000
            ).strftime("%d %b %H:%M:%S")
        else:
            created_date = u"N/A"

        # ----------- HEADER HTML --------------
        header_html = u"""
        <div class='incident-header'>

            <div class='incident-header-top'>

                <div class='incident-header-left'>
                    <div class='incident-title-text'>%s</div>
                    <div class='incident-title-badge'>%s</div>
                </div>

                <div class='incident-header-date'>
                    <span class='incidentDate'>%s</span>
                </div>

            </div>

            <div class='incident-header-middle'>
                %s
            </div>

            <div class='incident-meta-row'>

                <div class='meta-item-vertical'>
                    <div class='meta-label'>Assign</div>
                    <div class='meta-value'>%s</div>
                </div>

                <div class='meta-item-vertical'>
                    <div class='meta-label'>Assign Type</div>
                    <div class='meta-value'>%s</div>
                </div>

                <div class='meta-item-vertical'>
                    <div class='meta-label'>Status</div>
                    <div class='meta-value'>
                        <span class='badge badge-status-open'>%s</span>
                    </div>
                </div>

                <div class='meta-item-vertical'>
                    <div class='meta-label'>Criticality</div>
                    <div class='meta-value'>
                        <span class='badge badge-critical'>%s</span>
                    </div>
                </div>

            </div>

        </div>
        """ % (
            title,
            incident_id,
            created_date,
            description,
            assignee,
            assign_type,
            status,
            criticality
        )

        # ----------- CONTENT STRUCTURE --------------
        incident_content = {
            "RCA (Root Cause Analysis)": safe_rca(conclusion)
        }

        # ----------- DETECTIONS HANDLING --------------
        detections = item.get("detections")
        print(isinstance(detections, dict))

        if detections:

            event = detections

            exclude_keys = [
                "id", "messageid", "streamid", "detectionid", "tenant",
                "customer", "eventreceivedtime", "eventtime", "debug",
                "steps", "agent_name", "agent_desc", "template", "status",
                "starttime", "endtime", "execution_id", "eventtype",
                "eventid", "score", "clusters", "derived"
            ]

            detection_details = {}
            print(detections)

            for key, val in event.items():

                if key in exclude_keys:
                    continue

                if val is None:
                    continue

                if isinstance(val, basestring) and not val.strip():
                    continue

                if val in [[], {}]:
                    continue

                formatted_key = key.replace("_", " ").title()

                detection_details[formatted_key] = unicode(val)

            if detection_details:
                incident_content["Detection Details"] = detection_details

        incidents[header_html] = incident_content

    return {
        "result": {
            "data": incidents
        }
    }

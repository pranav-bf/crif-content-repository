from datetime import datetime


def format():
    return "detailCard"


# this to return query to be used for rendering widget and its parameters
def query():
    return [
        {
            "query": """
                SELECT
                    id,
                    name,
                    description
                FROM incidentdetails;
            """,
            "parameters": {}
        },
        {
            "query": """
                SELECT DISTINCT ON (incidentid)
                       incidentid,
                       actioncomment,
                       actiontime
                FROM incidentactivities
                WHERE actioncomment LIKE '<p>%'
                ORDER BY incidentid, actiontime DESC;
            """,
            "parameters": {}
        }
    ]



def render(results):

    incidents = results[0]
    activities = results[1]

    # Map incidentid -> latest comment (since query already gives DISTINCT ON latest)
    comment_map = {}

    for row in activities:
        inc_id = row.get("incidentid")
        comment = row.get("actioncomment")

        if inc_id and comment:

            # Remove <p> tags if present
            comment = comment.replace("<p>", "").replace("</p>", "")

            if inc_id not in comment_map:
                comment_map[inc_id] = []

            comment_map[inc_id].append(comment)

    # Group by detection name (since one detection per result set)
    grouped = {}

    for inc in incidents:

        name = inc.get("name")
        desc = inc.get("description")
        inc_id = inc.get("id")

        if name not in grouped:
            grouped[name] = {
                "description": desc,
                "incident_ids": []
            }

        grouped[name]["incident_ids"].append(inc_id)

    full_html = ""

    for name in grouped:

        desc = grouped[name]["description"]
        incident_ids = grouped[name]["incident_ids"]

        comments_html = ""

        for iid in incident_ids:
            if iid in comment_map:
                for comment in comment_map[iid]:
                    comments_html += """
                        <div class="ic-comment-row">
                            <span class="ic-case-id">%s</span>
                            <span class="ic-comment-text">%s</span>
                        </div>
                    """ % (iid, comment)

        if comments_html:
            comments_block = """
                <div class="ic-comments-block">
                    <div class="ic-comments-label">Comments</div>
                    %s
                </div>
            """ % comments_html
        else:
            comments_block = """
                <div class="ic-comments-block">
                    <div class="ic-comments-label">Comments</div>
                    <div class="ic-comment-text">No comments available</div>
                </div>
            """

        full_html += """
            <div class="ic-detection-card">
                <div class="ic-detection-header">
                    <div class="ic-detection-title">%s</div>
                    <div class="ic-detection-description">%s</div>
                </div>
                %s
            </div>
        """ % (name, desc, comments_block)

    # Engine-safe return (no visible keys)
    return {
        "result": {
            "data": {
                "": {
                    "": full_html
                }
            }
        }
    }

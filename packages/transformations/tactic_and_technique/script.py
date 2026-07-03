

def transform(event):
    print("hiiiii")
    technique_id = event.get("technique")
    print("technique_id", technique_id)

    if not technique_id:
        return event

    result = tpi.query(
        "MitreTechniques",
        "technique_id = ?",
        [technique_id]
    )

    rows = result.get("rows", [])
    print("rows", rows)

    if not rows:
        return event

    row = rows[0]

    tactic_name = row[0]
    tactic_id = row[1]
    technique_name = row[2]
    sub_technique_name = row[3]
    technique_id = row[4]

    # Add tactic field
    event["tactic"] = "%s (%s)" % (tactic_name, tactic_id)

    # Update existing technique field
    if sub_technique_name:
        event["technique"] = "%s / %s (%s)" % (
            technique_name,
            sub_technique_name,
            technique_id
        )
    else:
        event["technique"] = "%s (%s)" % (
            technique_name,
            technique_id
        )
    print("complete event", event)
    return event

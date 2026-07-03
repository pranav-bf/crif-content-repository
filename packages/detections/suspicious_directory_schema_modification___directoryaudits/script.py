# --------------------------------------------------------------------
# Directory Schema / Extension Attribute Update Detection
# --------------------------------------------------------------------

SCHEMA_EVENTS = {
    "Add directory extension attribute",
    "Update schema extension"
}

# Legitimate application schema registrations (safe)
APP_SCHEMA_OWNERS = [
    "app-reg-bot@domain.com",
    "schema-service@domain.com"
]

# Sensitive or suspicious attribute keywords
SENSITIVE_ATTRIBUTE_KEYWORDS = [
    "ssn",
    "token",
    "tokenkey",
    "secret",
    "apiKey",
    "privileged",
    "credential"
]


# ---------------------- Helper Functions ---------------------- #

def _is_legitimate_app_registration(actor):
    if not actor:
        return False
    return actor.lower() in [a.lower() for a in APP_SCHEMA_OWNERS]


def _is_sensitive_attribute(event):
    """
    Detect sensitive extension attributes being added or modified.
    Example:
        change_new_value: {"Name": "SSN"} or {"Attribute": "TokenKey"}
    """
    new_val = str(event.get("change_new_value") or "").lower()
    return any(k.lower() in new_val for k in SENSITIVE_ATTRIBUTE_KEYWORDS)


def _correlate_new_service_principal(event):
    """
    SIEM enrichment may add:
        event['recent_sp_created'] = True/False
    """
    return event.get("recent_sp_created") is True


def window():
    return None

 
def groupby():
    return None



def algorithm(event):

    score = 0.0
    valid = True

    activity = event.get("event_subtype")
    actor = event.get("source_email")

    # 1. Must be schema or extension attribute update
    if activity not in SCHEMA_EVENTS:
        valid = False

    # 2. Exclude legitimate application-driven schema registrations
    elif _is_legitimate_app_registration(actor):
        valid = False

    # 3. Sensitive attribute change detection
    sensitive = _is_sensitive_attribute(event)

    # 4. Correlate with recent Service Principal creation events
    correlated_sp =False
    if event.get("recent_sp_created"):
      correlated_sp=True

    # ---------------------- Single-Return Score ---------------------- #
    if valid:
        # High severity if sensitive attribute added or correlated to SP creation
        if sensitive or correlated_sp:
            score = 0.90
        else:
            score = 0.75

    return score


# ---------------------- Context ---------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    attribute = event.get("destination_object_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    src_ip = event.get("source_ip")
    correlated_sp = event.get("recent_sp_created")

    return (
        "A directory schema or extension attribute update was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' on schema attribute '{attr}'. "
        "Old value: '{old}', new value: '{new}'. Source IP: {ip}. "
        "Recent service principal creation correlation: {sp}. "
        "This may indicate data exfiltration preparation or privilege abuse."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        attr=attribute,
        old=old_v,
        new=new_v,
        ip=src_ip,
        sp="Yes" if correlated_sp else "No"
    )


# ---------------------- Metadata ---------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Privilege Escalation (TA0004)"


def technique():
    return "Modify Directory Attributes (T1098.003)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "event_subtype",
        "destination_object_name",
        "change_old_value",
        "change_new_value",
        "source_ip",
        "recent_sp_created"
    ])


def entity(event):
    # Entity = schema attribute being modified
    return {"derived": False, "value": event.get("destination_object_name"), "type": "schemaattribute"}

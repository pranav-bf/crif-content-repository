# -------------------------------------------------------
# Suspicious Service Principal Modification Detection
# -------------------------------------------------------

# Trigger activities
SP_MOD_ACTIVITIES = {
    "Update application",
    "Add app role assignment",
    "Update service principal"
}

# Allowed automation / CI/CD app IDs
TRUSTED_AUTOMATION_APPS = [
    "11111111-2222-3333-4444-555555555555",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
]

# High-risk modified properties
HIGH_RISK_PROPERTIES = [
    "AppRoleAssignment",
    "RequiredResourceAccess",
    "Oauth2PermissionScopes",
    "AppRoles"
]

# Actor must be human (not service principal)
def _actor_is_human(event):
    actor_type = event.get("source_account_type")
    if not actor_type:
        return True  # default assume human if not specified
    return actor_type.lower() not in ["serviceprincipal", "application"]


def _is_trusted_automation(event):
    actor_id = event.get("source_id")
    return actor_id in TRUSTED_AUTOMATION_APPS


def _is_high_risk_property(event):
    prop = event.get("change_property_name")
    if not prop:
        return False
    prop_l = prop.lower()
    return any(h.lower() in prop_l for h in HIGH_RISK_PROPERTIES)


def window():
    return None


def groupby():
    return None



def algorithm(event):

    score = 0.0
    valid = True

    # 1. Must be Service Principal target
    if event.get("destination_object_type") != "ServicePrincipal":
        valid = False

    # 2. Must match activityDisplayName
    elif event.get("event_subtype") not in SP_MOD_ACTIVITIES:
        valid = False

    # 3. Exclude known automation or DevOps pipelines
    elif _is_trusted_automation(event):
        valid = False

    # 4. Alert only for human-initiated updates
    elif not _actor_is_human(event):
        valid = False

    # 5. Only alert for high-risk property changes
    elif not _is_high_risk_property(event):
        valid = False

    # 6. Optional: Evaluate escalation but DO NOT change final score
    else:
        old_v = str(event.get("change_old_value") or "").lower()
        new_v = str(event.get("change_new_value") or "").lower()

        # You may track escalation with stats/add or dissipate, 
        # but score remains the same.
        if "graph" in new_v and "graph" not in old_v:
            pass   # escalation detected but no change to score

    # If all checks passed, fixed score
    if valid:
        score = 0.90

    return score

# ---------------- Context ---------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    service_name = event.get("service_name")
    target_name = event.get("destination_object_name")
    prop = event.get("change_property_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    activity = event.get("event_subtype")
    src_ip = event.get("source_ip")

    msg = (
        "A service principal modification was detected. Actor '{actor}' ({actor_email}) performed "
        "activity '{activity}' on service principal '{target}'. "
        "Property '{prop}' changed from '{old}' to '{new}'. "
        "Source IP: {ip}. Logged by service: {service}. "
        "This may indicate unauthorized app registration modification or privilege escalation."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        target=target_name,
        prop=prop,
        old=old_v,
        new=new_v,
        ip=src_ip,
        service=service_name
    )

    return msg


# ---------------- Metadata ---------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Privilege Escalation (TA0004)"


def technique():
    return "Modify Cloud Application Registration (T1098.003)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "source_id",
        "destination_object_name",
        "destination_object_type",
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "event_subtype",
        "service_name",
        "source_ip"
    ])


def entity(event):
    # Entity = modified Service Principal App ID
    sp_id = event.get("destination_object_id")
    return {"derived": False, "value": sp_id, "type": "serviceprincipal"}

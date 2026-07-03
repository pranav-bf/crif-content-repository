# ------------------------------------------------------------
# Application Consent / Permission Grant Detection
# ------------------------------------------------------------

CONSENT_EVENTS = {
    "Consent to application",
    "Add delegated permission grant"
}


# Known safe enterprise apps (internal apps)
SAFE_APP_IDS = [
    "11111111-2222-3333-4444-555555555555",
    "aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
]

# High-risk Graph API permissions
HIGH_RISK_SCOPES = [
    "mail.read",
    "mail.readwrite",
    "user.readwrite.all",
    "directory.readwrite.all",
    "offline_access"
]

# Multi-tenant indicator (ServicePrincipal "appOwnerOrganizationId" != tenant)
MULTITENANT_MARKERS = ["MultiTenant", "multiTenant", "multi-tenant"]


# --------------------- Helpers --------------------- #

def _is_safe_enterprise_app(app_id):
    return app_id in SAFE_APP_IDS


def _high_risk_permission(event):
    new_val = str(event.get("change_new_value") or "").lower()
    return any(scope in new_val for scope in HIGH_RISK_SCOPES)


def _is_multitenant(event):
    new_val = str(event.get("change_new_value") or "").lower()
    return any(m.lower() in new_val for m in MULTITENANT_MARKERS)


def _actor_is_human(event):
    actor_type = event.get("source_account_type")
    if not actor_type:
        return True
    return actor_type.lower() not in ["application", "serviceprincipal"]


def window():
    return None


def groupby():
    return None



def algorithm(event):

    score = 0.0
    valid = True

    activity = event.get("event_subtype")
    actor = event.get("source_email")
    app_id = event.get("destination_object_id")

    # 1. Consent / Delegated permission events only
    if activity not in CONSENT_EVENTS:
        valid = False

    # 2. Exclude safe internal enterprise apps
    elif _is_safe_enterprise_app(app_id):
        valid = False

    # 3. Must be human actor (exclude service principals)
    elif not _actor_is_human(event):
        valid = False

    # 4. High-risk permissions check
    risky_scope = _high_risk_permission(event)

    # 5. Multi-tenant consent check
    multitenant = _is_multitenant(event)

    # ---------------- Single Return Scoring ---------------- #

    if valid:
        # High severity if risky scope OR multitenant consent
        if risky_scope or multitenant:
            score = 0.90
        else:
            score = 0.75

    return score


# --------------------- Context --------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    app_name = event.get("destination_object_name")
    app_id = event.get("destination_object_id")
    new_val = event.get("change_new_value")
    src_ip = event.get("source_ip")

    return (
        "An application consent or permission grant event occurred. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' for application '{app}' (AppId: {id}). "
        "New permission assigned: '{perm}'. Source IP: {ip}. "
        "This may indicate OAuth abuse or malicious delegated permission consent."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        app=app_name,
        id=app_id,
        perm=new_val,
        ip=src_ip
    )


# --------------------- Metadata --------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Credential Access (TA0006)"


def technique():
    return "Illicit Consent Grant (T1525)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "destination_object_id",
        "destination_object_name",
        "event_subtype",
        "change_new_value",
        "source_ip"
    ])


def entity(event):
    # Entity = the application receiving consent
    return {"derived": False, "value": event.get("destination_object_id"), "type": "application"}

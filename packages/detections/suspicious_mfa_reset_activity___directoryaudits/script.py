# ------------------------------------------------------------
# Authentication Method / MFA Reset Detection
# ------------------------------------------------------------

MFA_EVENTS = {
    "Register security info",
    "Reset MFA",
    "Update authentication methods policy"
}

# Keywords to identify privileged/VIP users
VIP_KEYWORDS = ["vip", "executive", "c-level", "privileged", "admin"]

# Helpdesk service accounts (allowed to reset MFA only if ticket exists)
HELPDESK_ACCOUNTS = [
    "helpdesk@domain.com",
    "support@domain.com"
]


# -------------------- Helper Functions -------------------- #

def _is_vip_user(user_display):
    if not user_display:
        return False
    name_l = user_display.lower()
    return any(k in name_l for k in VIP_KEYWORDS)


def _has_itsm_ticket(event):
    """
    Enriched from external system: event['change_ticket'] = 'INC1234'
    """
    ticket = event.get("change_ticket")
    return bool(ticket and ticket not in ["", None, "UNKNOWN"])


def _is_helpdesk_actor(actor):
    if not actor:
        return False
    return actor.lower() in [h.lower() for h in HELPDESK_ACCOUNTS]


def _preceded_by_failed_logins(event):
    """
    Your SIEM may enrich this as:
        event['recent_failed_logins'] = <int>
        event['risk_level'] = 'High'/'Medium'/'None'
    """
    failures = event.get("recent_failed_logins", 0)
    risk = event.get("risk_level", "").lower()

    if failures >= 3:
        return True
    if risk in ["high", "medium"]:
        return True
    return False


def window():
    return None


def groupby():
    return None


def algorithm(event):

    score = 0.0
    valid = True

    actor = event.get("source_email")
    activity = event.get("event_subtype")
    target_user = event.get("destination_account_name")

    # 1. Event must be MFA reset / auth-method change
    if activity not in MFA_EVENTS:
        valid = False

    # 2. Exclude helpdesk accounts *unless* ticket exists
    elif _is_helpdesk_actor(actor) and _has_itsm_ticket(event):
        valid = False

    # 3. Only alert for privileged / VIP accounts
    elif not _is_vip_user(target_user):
        valid = False

    # 4. Check preceding risk or login failures
    risk_detected = _preceded_by_failed_logins(event)

    # -------------------- Single-Return Scoring -------------------- #

    if valid:
        # Higher severity if recent failures or risk events occurred
        if risk_detected:
            score = 0.90
        else:
            score = 0.75

    return score


# -------------------- Context -------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    target = event.get("destination_account_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    src_ip = event.get("source_ip")
    failures = event.get("recent_failed_logins", 0)
    risk = event.get("risk_level", "None")

    return (
        "An MFA or authentication method reset was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' for user '{target}'. "
        "Old value: '{old}', new value: '{new}'. Source IP: {ip}. "
        "Recent failed logins: {failures}. Risk level: {risk}. "
        "This may indicate credential compromise or unauthorized MFA removal."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        target=target,
        old=old_v,
        new=new_v,
        ip=src_ip,
        failures=failures,
        risk=risk
    )


# -------------------- Metadata -------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Privilege Escalation (TA0004)"


def technique():
    return "Valid Accounts (T1078)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "destination_account_name",
        "event_subtype",
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "source_ip",
        "recent_failed_logins",
        "risk_level",
        "change_ticket"
    ])


def entity(event):
    return {"derived": False, "value": event.get("destination_account_name"), "type": "user"}



PASSWORD_EVENTS = {
    "Update password policy",
    "Update self-service password reset policy"
}

# Known automation / scripts that perform legitimate policy updates
AUTOMATION_SCRIPTS = [
    "password-bot@domain.com",
    "policy-automation@domain.com",
    "config-service@domain.com"
]

# Keywords indicating strong → weak password or SSPR weakening
WEAKENING_PATTERNS = [
    "none",
    "disabled",
    "false",
    "notrequired"
]


HIGH_PRIV_ADMIN_GROUPS = [
    "global administrators",
    "privileged role administrators",
    "password administrators"
]


# ------------------------- Helper Functions ------------------------- #

def _is_automation_script(actor):
    if not actor:
        return False
    return actor.lower() in [a.lower() for a in AUTOMATION_SCRIPTS]


def _policy_weakened(event):
    """
    Detect:
       Strong → None
       Enabled → Disabled
       required → not required
    """
    old_val = str(event.get("change_old_value") or "").lower()
    new_val = str(event.get("change_new_value") or "").lower()

    # Policy was strengthened? Ignore
    if old_val == new_val:
        return False

    # Weakening condition: new value contains a weakening pattern
    return any(w in new_val for w in WEAKENING_PATTERNS)


def _actor_is_security_admin(event):
    """
    SIEM enrichment:
       event['actor_admin_group'] = "Password Administrators"
    """
    group = str(event.get("actor_admin_group") or "").lower()
    return any(admin_group in group for admin_group in HIGH_PRIV_ADMIN_GROUPS)


def window():
    return None


def groupby():
    return None


def algorithm(event):

    score = 0.0
    valid = True

    activity = event.get("event_subtype")
    actor = event.get("source_email")

    # 1. Must be password or SSPR policy update
    if activity not in PASSWORD_EVENTS:
        valid = False

    # 2. Exclude known automation scripts
    elif _is_automation_script(actor):
        valid = False

    # 3. Check if policy was weakened
    weakened = _policy_weakened(event)

    # 4. Actor admin group enrichment
    actor_is_admin = _actor_is_security_admin(event)

    # ------------------------- Single Return Scoring ------------------------- #
    if valid:
        # High severity if weakened or done by non-admin from outside security admin groups
        if weakened or not actor_is_admin:
            score = 0.90
        else:
            score = 0.75

    return score


# ------------------------- Context ------------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    prop = event.get("change_property_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    group = event.get("actor_admin_group", "Unknown")
    ip = event.get("source_ip")

    return (
        "A password or SSPR policy modification was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}'. "
        "Property '{prop}' changed from '{old}' to '{new}'. "
        "Actor admin group: {group}. Source IP: {ip}. "
        "This may indicate weakening of password or self-service reset security."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        prop=prop,
        old=old_v,
        new=new_v,
        group=group,
        ip=ip
    )


# ------------------------- Metadata ------------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Modify Authentication Mechanisms (T1556)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "event_subtype",
        "change_old_value",
        "change_new_value",
        "change_property_name",
        "source_ip",
        "actor_admin_group"
    ])


def entity(event):
    # Entity = the policy being modified
    return {"derived": False, "value": event.get("change_property_name"), "type": "passwordpolicy"}

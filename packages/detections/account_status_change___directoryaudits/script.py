# --------------------------------------------
# Account Enable / Disable Detection
# --------------------------------------------

PRIVILEGED_CATEGORIES = ["Admin", "VIP", "Privileged", "Executive"]

# Known automation accounts (AAD Connect, SCIM apps, Provisioning SPNs)
AUTOMATION_KEYWORDS = ["sync", "connect", "scim", "provision", "service"]

# Known IT admin groups (actor should be suppressed)
KNOWN_ADMIN_GROUPS = ["Global Administrators", "Privileged Role Administrators"]



def window():
    # Suppress identical events from same actor for 60 seconds
    return '60s'


def groupby():
    # Group by target account to detect repeated enable/disable
    return ["destination_account_name"]

def _is_privileged_or_vip(user_display):
    if not user_display:
        return False
    name_l = user_display.lower()
    return any(tag.lower() in name_l for tag in PRIVILEGED_CATEGORIES)


def _is_known_admin_group(event):
    group_type = event.get("destination_account_type")
    if not group_type:
        return False
    return any(g.lower() in group_type.lower() for g in KNOWN_ADMIN_GROUPS)


def _is_account_status_change(event):
    """
    Check if modified property 'AccountEnabled' changed
    true -> false  OR  false -> true
    """
    prop = event.get("change_property_name")
    if not prop or prop.lower() != "accountenabled":
        return False

    old_v = str(event.get("change_old_value")).lower()
    new_v = str(event.get("change_new_value")).lower()

    valid_states = ["true", "false"]

    if old_v in valid_states and new_v in valid_states and old_v != new_v:
        return True

    return False


# ------------------ Detection Algorithm ------------------ #

def algorithm(event):
    source_upn = event.get("source_email")
    actor_name = event.get("source_account_name")
    target_user = event.get("destination_account_name")
    target_type = event.get("destination_account_type")
    service = event.get("service_name")

    # 1. Must be an AccountEnabled change
    if not _is_account_status_change(event):
        return 0.0


    # 3. Suppress if event originates from known admin groups
    if _is_known_admin_group(event):
        return 0.0

    # 4. Only alert for privileged/VIP accounts
    if not _is_privileged_or_vip(target_user):
        return 0.0

    # 5. Success only (ignore failures)
    status = event.get("event_status")
    if status != "success":
        return 0.0

    # Passed all filters
    return 0.75


# ------------------ Context Block ------------------ #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    target = event.get("destination_account_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    src_ip = event.get("source_ip")
    service = event.get("service_name")

    msg = (
        "A user account status was modified. Actor '{actor}' ({actor_email}) changed "
        "AccountEnabled from '{old_v}' to '{new_v}' for user '{target}'. "
        "Source IP: {src_ip}. Service: {service}. "
        "This may indicate unauthorized account reactivation or disabling."
    ).format(
        actor=actor,
        actor_email=actor_email,
        target=target,
        old_v=old_v,
        new_v=new_v,
        src_ip=src_ip,
        service=service
    )

    return msg


def criticality():
    return "HIGH"


def tactic():
    return "Privilege Escalation (TA0004)"


def technique():
    return "Valid Accounts (T1078)"


def artifacts():
    return stats.collect([
        "event_id",
        "event_subtype",
        "source_email",
        "source_account_name",
        "destination_account_name",
        "destination_account_type",
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "event_status",
        "service_name",
        "source_ip"
    ])


def entity(event):
    # Entity = target user account
    return {"derived": False, "value": event.get("destination_account_name"), "type": "accountname"}

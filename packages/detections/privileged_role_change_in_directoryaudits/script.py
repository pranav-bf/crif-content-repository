# --------------------------------------------
# Admin Role Assignment Change Detection
# --------------------------------------------

# High-risk admin roles to alert on
HIGH_PRIV_ROLES = {
    "Global Administrator",
    "Company Administrator",
    "Privileged Role Administrator",
    "Application Administrator"
}


# Trusted IP ranges (example)
TRUSTED_IPS = ["10.", "192.168.", "172.16."]


def window():
    return None


def groupby():
    return None




def _is_trusted_ip(ip):
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in TRUSTED_IPS)


def _is_pim_event(service_name):
    if not service_name:
        return False
    return service_name.lower() == "privilegedaccess"


# ----------- Algorithm Logic -----------

def algorithm(event):
    """
    Detect Add/Remove member to HIGH PRIVILEGE ADMIN ROLES.
    """

    activity = event.get("event_subtype")     # activityDisplayName → event_subtype
    service_name = event.get("service_name")
    source_upn = event.get("source_email")
    src_ip = event.get("source_ip")
    role_name = event.get("destination_object_name")  # target group name (role)
    event_status = event.get("event_status")

    # 1. Must be Add / Remove admin role member
    if activity not in ["Add member to role", "Remove member from role"]:
        return 0.0

    # 2. Must be successful
    if event_status != "success":
        return 0.0

    # 3. Target role must be privileged
    if not role_name or role_name not in HIGH_PRIV_ROLES:
        return 0.0


    # 5. Suppress: Trusted corporate IP ranges
    if _is_trusted_ip(src_ip):
        return 0.0

    # 6. Suppress: PIM events
    if _is_pim_event(service_name):
        return 0.0

    # If passed all FP checks → HIGH CONFIDENCE
    return 0.90


# ----------- Context -----------

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    role_name = event.get("destination_object_name")
    target_user = event.get("destination_account_name")
    src_ip = event.get("source_ip")
    service = event.get("service_name")
    activity = event.get("event_subtype")

    msg = (
        "A privileged role change was detected: '{activity}'. "
        "Actor '{actor}' ({actor_email}) attempted to modify role '{role}'. "
        "Target user: '{target_user}'. "
        "Source IP: {src_ip}. Logged by service: {service}. "
        "This action affects a high-privilege admin role and may indicate "
        "privilege escalation or unauthorized role assignment."
    ).format(
        activity=activity,
        actor=actor,
        actor_email=actor_email,
        role=role_name,
        target_user=target_user,
        src_ip=src_ip,
        service=service
    )

    return msg


# ----------- Metadata -----------

def criticality():
    return "HIGH"


def tactic():
    return "Privilege Escalation (TA0004)"


def technique():
    return "Valid Accounts: Privileged Role Modification (T1078)"


def artifacts():
    return stats.collect([
        "event_id",
        "event_subtype",
        "source_ip",
        "source_email",
        "source_account_name",
        "destination_object_name",
        "destination_account_name",
        "destination_object_type",
        "event_status",
        "service_name",
        "correlation_id"
    ])


def entity(event):
    """
    Primary entity = role being modified.
    """
    role = event.get("destination_object_name")
    return {"derived": False, "value": role, "type": "ad_role"}

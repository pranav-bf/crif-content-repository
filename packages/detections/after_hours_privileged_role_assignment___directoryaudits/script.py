# ------------------------------------------------------------
# Privileged Role Assignment Outside Business Hours Detection
# ------------------------------------------------------------

ROLE_EVENTS = {
    "Add member to role",
    "Activate eligible role"
}

# Known break-glass / emergency access accounts
EMERGENCY_ACCOUNTS = [
    "breakglass@domain.com",
    "emergency.admin@domain.com"
]

# Maintenance hours (example: 1 AM – 2 AM)
MAINTENANCE_HOURS = [1]



def _in_maintenance_window(event):
    ts = event.get("event_time")
    if not ts:
        return False
    try:
        hour = int(ts.split("T")[1].split(":")[0])
        return hour in MAINTENANCE_HOURS
    except:
        return False


def _is_emergency_account(upn):
    if not upn:
        return False
    return upn.lower() in [e.lower() for e in EMERGENCY_ACCOUNTS]


def _is_unfamiliar_geo(event):
    geo = event.get("geo_risk")
    if geo == "Unfamiliar":
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

    # 1. Must be privileged role assignment action
    if activity not in ROLE_EVENTS:
        valid = False

    # 2. Exclude maintenance period changes
    elif _in_maintenance_window(event):
        valid = False

    # 3. Exclude emergency access accounts
    elif _is_emergency_account(actor):
        valid = False

    # 4. Must occur outside business hours
    elif _in_business_hours(event):
        valid = False

    # 5. Geo/IP risk (optional enrichment via SignInLogs)
    geo_high = _is_unfamiliar_geo(event)

    # ---------------- Final Scoring (single score) ---------------- #
    if valid:
        # High severity if geo is unfamiliar
        if geo_high:
            score = 0.90
        else:
            score = 0.75

    return score


# ---------------------- Context ---------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    target_role = event.get("destination_object_name")
    ts = event.get("event_time")
    src_ip = event.get("source_ip")
    geo = event.get("geo_risk") or "Unknown"

    return (
        "A privileged role assignment event occurred outside business hours. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' on role '{role}' at time '{ts}'. "
        "Source IP: {ip}. Geo risk: {geo}. "
        "This may indicate unauthorized privilege escalation."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        role=target_role,
        ts=ts,
        ip=src_ip,
        geo=geo
    )


# ---------------------- Metadata ---------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Privilege Escalation (TA0004)"


def technique():
    return "Valid Accounts: Elevated Role Abuse (T1078)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "destination_object_name",
        "event_subtype",
        "event_time",
        "source_ip",
        "geo_risk"
    ])


def entity(event):
    # Entity = user performing after-hours role assignment
    return {"derived": False, "value": event.get("source_email"), "type": "user"}

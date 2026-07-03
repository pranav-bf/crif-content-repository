# --------------------------------------------------------------------
# Risk Policy Modification / Suppression Detection
# --------------------------------------------------------------------

RISK_POLICY_EVENTS = {
    "Update risk policy",
    "Disable user risk policy",
    "Update sign-in risk policy"
}

# Known security admin service accounts (allowed)
SECURITY_ADMIN_SERVICE_ACCOUNTS = [
    "secadmin-bot@domain.com",
    "security-automation@domain.com"
]

# Corporate IP ranges (trusted)
CORPORATE_IP_PREFIXES = [
    "10.",
    "172.16.",
    "192.168."
]



def _is_security_automation(upn):
    if not upn:
        return False
    upn_l = upn.lower()
    return upn_l in [a.lower() for a in SECURITY_ADMIN_SERVICE_ACCOUNTS]


def _is_corporate_ip(ip):
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in CORPORATE_IP_PREFIXES)


def _policy_disabled(event):
    """
    Detect: isPolicyEnabled: true -> false
    """
    old_val = str(event.get("change_old_value") or "").lower()
    new_val = str(event.get("change_new_value") or "").lower()

    return ("true" in old_val and "false" in new_val)


def window():
    return None


def groupby():
    return None



def algorithm(event):

    score = 0.0
    valid = True

    activity = event.get("event_subtype")
    actor = event.get("source_email")
    src_ip = event.get("source_ip")

    # 1. Must be risk policy change event
    if activity not in RISK_POLICY_EVENTS:
        valid = False

    # 2. Exclude authorized security admin automation accounts
    elif _is_security_automation(actor):
        valid = False

    # 3. Evaluate if policy was disabled (true → false)
    disabled = _policy_disabled(event)

    # 4. Risky if IP outside corporate network
    external_ip = not _is_corporate_ip(src_ip)

    # --------------------- Single Return Scoring --------------------- #
    if valid:
        # Highest severity when policy disabled *and* from external IP
        if disabled and external_ip:
            score = 0.90
        else:
            score = 0.75

    return score


# ------------------------- Context ------------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    ip = event.get("source_ip")
    activity = event.get("event_subtype")
    prop = event.get("change_property_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")

    return (
        "A risky sign-in or risk policy modification was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}'. "
        "Property '{prop}' changed from '{old}' to '{new}'. "
        "Actor IP: {ip}. This may indicate suppression of risk detections or MFA requirements."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        prop=prop,
        old=old_v,
        new=new_v,
        ip=ip
    )



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
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "source_ip"
    ])


def entity(event):
    # The entity is the risk policy being modified
    return {"derived": False, "value": event.get("change_property_name"), "type": "riskpolicy"}

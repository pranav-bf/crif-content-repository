# -----------------------------------------------------------------
# Directory Federation / Domain Configuration Change Detection
# -----------------------------------------------------------------

FEDERATION_EVENTS = {
    "Update domain",
    "Add domain",
    "Convert domain to federated"
}

# Known automation service principals or bots
TENANT_AUTOMATION_ACCOUNTS = [
    "domain-sync@domain.com",
    "config-bot@domain.com",
    "automation@domain.com"
]

# Keywords indicating external or suspicious domains
EXTERNAL_DOMAIN_KEYWORDS = [
    ".onmicrosoft.com",
    ".mail",
    ".xyz",
    ".cloud",
    ".external"
]


# ----------------------- Helper Functions ----------------------- #

def _is_automation_actor(upn):
    if not upn:
        return False
    upn_l = upn.lower()
    return upn_l in [a.lower() for a in TENANT_AUTOMATION_ACCOUNTS]


def _is_external_domain(event):
    """
    Example:
      destination_object_name = "attacker-controlled-domain.xyz"
    """
    domain = event.get("destination_object_name") or ""
    dom_l = domain.lower()
    return any(ext in dom_l for ext in EXTERNAL_DOMAIN_KEYWORDS)


def _domain_not_owned(event):
    """
    Your enrichment may add: event['domain_owned'] = True/False
    If unknown, treat as unowned → suspicious
    """
    owned = event.get("domain_owned")
    return owned is False



def window():
    return None


def groupby():
    return None



def algorithm(event):

    score = 0.0
    valid = True

    actor = event.get("source_email")
    activity = event.get("event_subtype")
    domain_name = event.get("destination_object_name")

    # 1. Must be federation/domain modification event
    if activity not in FEDERATION_EVENTS:
        valid = False

    # 2. Suppress known tenant-level automation
    elif _is_automation_actor(actor):
        valid = False

    # 3. Domain ownership check
    external = _is_external_domain(event)
    unowned = _domain_not_owned(event)

    # ----------------------- Single Return Score ----------------------- #

    if valid:
        # highest severity if domain is external or unowned
        if external or unowned:
            score = 0.90
        else:
            score = 0.75

    return score


# ----------------------- Context ----------------------- #

def context(event):

    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    domain = event.get("destination_object_name")
    ip = event.get("source_ip")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    domain_owned = event.get("domain_owned")

    return (
        "A directory federation or domain configuration change was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' on domain '{domain}'. "
        "Old value: '{old}', new value: '{new}'. Source IP: {ip}. "
        "Domain ownership status: {owned}. "
        "This action may indicate federation hijacking or rogue domain registration."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        domain=domain,
        old=old_v,
        new=new_v,
        ip=ip,
        owned="Owned" if domain_owned else "Unowned/Suspicious"
    )


# ----------------------- Metadata ----------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Persistence (TA0003)"


def technique():
    return "External Remote Services: Federation Abuse (T1133)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "destination_object_name",
        "event_subtype",
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "source_ip",
        "domain_owned"
    ])


def entity(event):
    # Entity = the domain modified
    return {"derived": False, "value": event.get("destination_object_name"), "type": "domain"}

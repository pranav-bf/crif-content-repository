# ------------------------------------------------------------
# App Proxy / API Connector Modification Detection
# ------------------------------------------------------------

CONNECTOR_EVENTS = {
    "Add onPremisesPublishingProfile",
    "Update API connector",
    "Delete API connector"
}

# Known managed / automation IPs
MANAGED_CONNECTOR_IPS = [
    "10.10.0.25",
    "10.10.0.26",
    "192.168.50.10"
]

# Known automation actors (service identities)
AUTOMATION_ACTORS = [
    "connector-service@domain.com",
    "api-bot@domain.com",
    "automation@domain.com"
]


# -------------------------- Helpers -------------------------- #

def _is_managed_connector_ip(ip):
    return ip in MANAGED_CONNECTOR_IPS


def _is_automation_actor(actor):
    if not actor:
        return False
    return actor.lower() in [a.lower() for a in AUTOMATION_ACTORS]


def _actor_is_human(event):
    """
    Human actor must have source_account_type != servicePrincipal/application
    """
    a_type = event.get("source_account_type") or ""
    return a_type.lower() not in ["application", "serviceprincipal"]


def _has_abuse_indicators(event):
    """
    SIEM enrichment may add:
        event['geo_risk'], event['ca_decision'], event['signin_anomaly']
    """
    geo = event.get("geo_risk", "").lower()
    ca = event.get("ca_decision", "").lower()
    sign_in = event.get("signin_anomaly", "").lower()

    if geo in ["unfamiliar", "impossibletravel"]:
        return True
    if ca in ["failed", "blocked"]:
        return True
    if sign_in in ["risk", "anomalous"]:
        return True

    return False


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

    # 1. Must be connector-related update
    if activity not in CONNECTOR_EVENTS:
        valid = False

    # 2. Exclude managed/automation connector infrastructure
    elif _is_managed_connector_ip(src_ip):
        valid = False

    # 3. Exclude automation identities
    elif _is_automation_actor(actor):
        valid = False

    # 4. Only alert for human-initiated changes
    elif not _actor_is_human(event):
        valid = False

    # 5. Correlate with CA/Sign-In anomalies
    abuse = _has_abuse_indicators(event)

    # ---------------------- Single Return Scoring ---------------------- #
    if valid:
        if abuse:
            score = 0.90   # strong signal
        else:
            score = 0.75   # normal manual connector modification

    return score


# -------------------------- Context -------------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    connector = event.get("destination_object_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    ip = event.get("source_ip")
    geo = event.get("geo_risk", "Unknown")
    ca = event.get("ca_decision", "N/A")
    signin = event.get("signin_anomaly", "N/A")

    return (
        "An App Proxy or API Connector modification was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' on connector '{connector}'. "
        "Values changed from '{old}' to '{new}'. Source IP: {ip}. "
        "Geo risk: {geo}, CA decision: {ca}, Sign-In anomaly: {signin}. "
        "This may indicate tampering with authentication flows or hybrid connector abuse."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        connector=connector,
        old=old_v,
        new=new_v,
        ip=ip,
        geo=geo,
        ca=ca,
        signin=signin
    )


# -------------------------- Metadata -------------------------- #

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
        "source_account_type",
        "event_subtype",
        "destination_object_name",
        "change_old_value",
        "change_new_value",
        "source_ip",
        "geo_risk",
        "ca_decision",
        "signin_anomaly"
    ])


def entity(event):
    return {"derived": False, "value": event.get("destination_object_name"), "type": "connector"}

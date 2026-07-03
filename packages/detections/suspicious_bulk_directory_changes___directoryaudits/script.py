# -----------------------------------------------------------
# Suspicious Bulk Modifications by Same Admin IP
# -----------------------------------------------------------

# Tunables
MIN_EVENTS = 10          # N = Minimum distinct directory changes

TRUSTED_IP_PREFIXES = ["10.", "172.16.", "192.168."]   # Corporate networks
AUTOMATION_IPS = ["10.1.5.20", "10.1.5.21"]            # Terraform / pipelines / SCIM apps

# Object types to check diversity
OBJ_TYPES = ["User", "Group", "App", "Application", "Role"]


def window():
    # Sliding window of T minutes
    return '10m'


def groupby():
    # Aggregate by source IP performing changes
    return ["source_ip"]



def _is_trusted_ip(ip):
    if not ip:
        return False
    return any(ip.startswith(p) for p in TRUSTED_IP_PREFIXES)


def _is_automation_ip(ip):
    return ip in AUTOMATION_IPS


def algorithm(event):
    score = 0.0

    # Increment per-event counter for this source IP
    change_count = stats.count("bulk_changes")

    # 1. Ignore until threshold
    if change_count < MIN_EVENTS:
        return 0.0

    src_ip = event.get("source_ip")

    # 2. Suppress trusted IPs
    if _is_trusted_ip(src_ip):
        return 0.0

    # 3. Suppress automation IPs
    if _is_automation_ip(src_ip):
        return 0.0

    # 4. Collect and evaluate unique object types
    obj_types = stats.accumulate(["destination_object_type"])
    unique_count = len(obj_types.get("destination_object_type", []))

    if unique_count < 2:
        return 0.0

    # 5. High confidence once threshold is reached
    if change_count >= MIN_EVENTS:
        score = 0.90

    # Cleanup (reset accumulator after raising alert)
    stats.dissipate(["destination_object_type"])

    return score


# ------------------- Context ------------------- #

def context(events):
    src_ip = events[0].get("source_ip") if events else "UNKNOWN"
    actor = events[0].get("source_account_name")
    msg = (
        "Suspicious bulk directory modifications detected from IP {ip}. "
        "Actor: {actor}. A total of 10 distinct directory changes were performed "
        "within a short time window. This may indicate account takeover or "
        "mass unauthorized configuration changes."
    ).format(
        ip=src_ip,
        actor=actor
    )

    return msg


# ------------------- Metadata ------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Modify Directory Services (T1484)"


def artifacts():
    return stats.collect([
        "source_ip",
        "source_account_name",
        "destination_object_name",
        "destination_object_type",
        "event_id",
        "event_subtype",
        "event_category",
        "change_property_name",
    ])


def entity(event):
    # Entity = IP doing mass changes
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}

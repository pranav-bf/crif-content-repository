import math
from collections import Counter


def window():
    return "10m"


def groupby():
    return ["source_ip"]


def shannon_entropy(s):
    if not s:
        return 0.0

    counts = Counter(s)
    length = len(s)

    entropy = 0.0
    for count in counts.values():
        p = float(count) / float(length)
        entropy -= p * math.log(p, 2)

    return entropy

def algorithm(event):
    host = event.get("source_device_name")
    url = event.get("url")

    url_entropy = shannon_entropy(url)

    if stats.count(host) > 20 and url_entropy > 3.8:
      return 1.0
    
    return 0.0

def context(event):
    return (
        "Suspicious DNS query activity detected from source IP "
        + str(event.get("source_ip")) +
        ". The system queried the domain "
        + str(event.get("host")) +
        ", which has an unusually long length and high character entropy. "
        "The DNS request was sent to destination IP "
        + str(event.get("destination_ip")) +
        " on port "
        + str(event.get("destination_port")) + ". "
        "This activity was allowed by policy ID "
        + str(event.get("policy_id")) +
        " on device "
        + str(event.get("source_device_name")) + ". "
        "The alert triggered because multiple DNS queries from the same source "
        "within a 10-minute window contained high-entropy domain names, a behavior "
        "commonly associated with domain generation algorithms used by malware."
    )


  
def criticality():
    return "CRITICAL"

def tactic():
    return "Command and Control (TA0011)"

def technique():
    return "Application Layer Protocol (T1071)"

def artifacts(stats):
    return stats.collect(["source_ip", "destination_ip", "destination_port", "policy_id"])

def entity(event):
    return {
        "derived": False,
        "value": event.get("source_ip"),
        "type": "ipaddress"
    }

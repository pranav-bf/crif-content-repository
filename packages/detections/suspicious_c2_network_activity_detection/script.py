import re


# Common attacker-controlled or suspicious ports
C2_PORTS = [
    4444,  # Metasploit / reverse shell
    8081,  # Cobalt Strike / RAT variants
    1337,  # Custom RATs
    9001,  # Tor proxy
    5985, 5986,  # WinRM
    2222,  # Alternate SSH backdoor
    53,    # DNS tunneling
    443,   # HTTPS beaconing (only if suspicious IP)
    80     # HTTP beaconing (non-standard)
]

# # Known malicious or suspicious external IP ranges (examples - replace with your TI feed)
# SUSPICIOUS_IP_PATTERNS = [
#     r"^185\.100\.",   # Known C2 infra (example)
#     r"^45\.13\.",     # Known VPS abuse networks
#     r"^103\.145\.",   # Asian bulletproof hosting
#     r"^198\.51\.100\.",  # RFC test/malicious placeholders
#     r"^203\.0\.113\.",   # RFC test/malicious placeholders
# ]


def window():
    return '5m'  # Monitors traffic in a 5-minute window

def groupby():
    return ['source_ip']  # Grouping by the external IP to track multiple connections

def _is_external_ip(ip):
    """
    Check if an IP is external (not RFC1918 internal range)
    """
    if not ip or ip in ["-", "UNKNOWN", "::1", "127.0.0.1"]:
        return False
    private_ranges = [
        r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\."
    ]
    for p in private_ranges:
        if re.match(p, ip):
            return False
    return True



def _is_suspicious_ip(ip):
    """
    Match IPs against known malicious or suspicious network ranges.
    """
    if not ip:
        return False
    malicious_ip = tpi.query("MaliciousIP", "ip = ?", [ip])

    if not malicious_ip or not malicious_ip.get('rows'):
        return 0.0

    malicious_ips = [row[0] for row in malicious_ip.get('rows', [])]
    if ip in malicious_ips:
      return True
    return False



  

def algorithm(event):
    evt_id = str(event.get("event_id"))
    dest_ip = event.get("destination_ip")
    dest_port = int(event.get("destination_port", 0))
    src_ip = event.get("source_ip")
    host = event.get("host")

    # Accept network connection events (e.g., Sysmon EventID 3, firewall logs)
    if evt_id not in ["3", "5156", "5158"]:  # Sysmon / Windows Firewall
        return 0.0
      
    if not _is_external_ip(dest_ip):
        return 0.0

    if _is_suspicious_ip(dest_ip):
        return 0.95  # High confidence – matches known C2 IP

    if dest_port in C2_PORTS:
        return 0.75  # Medium-high confidence – matches known C2 port

    return None

def context(event_data):
    src_ip = event_data.get("source_ip")
    dest_ip = event_data.get("destination_ip")
    dest_port = event_data.get("destination_port")
    host = event_data.get("host")

    return (
        "Potential C2 communication detected: host '%s' (source IP: %s) initiated an "
        "outbound connection to %s:%s. The destination appears external or suspicious "
        "based on threat intelligence and known C2 port patterns."
    ) % (host, src_ip, dest_ip, str(dest_port))

def criticality():
    return 'HIGH'

def tactic():
    return 'Command and Control (TA0011)'

def technique():
    return 'Application Layer Protocol (T1071/001)'

def artifacts():
    return stats.collect(['host', 'destination_ip', 'destination_port', 'event_id',"source_ip"])

def entity(event):
    return {
        'derived': False,
        'value': event.get('destination_ip'),
        'type': 'ipaddress'
    }
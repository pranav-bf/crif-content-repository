def window():
    return None

def groupby():
    # Pair-wise between internal hosts
    return None

def algorithm(event):
    src_ip = event.get('source_ip', '') or ''
    dst_ip = event.get('destination_ip', '') or ''

    # Both private?
    is_priv_src = src_ip.startswith(('10.', '172.', '192.168.'))
    is_priv_dst = dst_ip.startswith(('10.', '172.', '192.168.'))

    if is_priv_src and is_priv_dst:
        try:
            s1, s2, _, _ = src_ip.split('.')
            d1, d2, _, _ = dst_ip.split('.')
            # Different /16 → possible cross-subnet movement
            if (s1, s2) != (d1, d2):
                return 0.7
        except Exception:
            return 0.0
    return 0.0

def context(event):
    return (
        "Possible lateral movement between internal hosts {src} and {dst} across "
        "different internal ranges."
    ).format(
        src=event.get('source_ip'),
        dst=event.get('destination_ip')
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Lateral Movement'

def technique():
    return 'Internal Network Scanning (T1046)'

def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'network_protocol', 'network_direction'])

def entity(event):
    """
    Identifies the primary entity related to this detection.
    Can be directly from event attribute or derived.
    """
    return {
        "derived": False,
        "value": event.get("source_ip", "unknown"),
        "type": "ipaddress"
    }
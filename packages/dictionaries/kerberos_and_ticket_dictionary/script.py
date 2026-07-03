import json
import time
import calendar
from datetime import datetime, timedelta
AUTH_EVENT_IDS = set([4768, 4769, 4770, 4771, 4662])



def init(event):
  return "initialization completed"


def criteria(meta):
    return (
        meta.get('provider') == 'Microsoft' and
        meta.get('group') == 'Windows' and
        meta.get('type') == 'Audit'
    )

def drop(event):
    if event.get("EventID") in AUTH_EVENT_IDS:
      return False
    else:
      return True


def timestamp(event):
    datestring = event.get("EventTime")

    dt_ist = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")
    dt_utc = dt_ist - timedelta(hours=5, minutes=30)

    epoch_time = calendar.timegm(dt_utc.timetuple())
    return int(epoch_time * 1000)


def message(event):
    event_id = event.get("EventID")
    host = event.get("Hostname", "UNKNOWN")
    user = event.get("SubjectUserName", "UNKNOWN")

    if event_id == 4768:
        return (
            "Kerberos TGT request detected on host {} "
            "for account {} from source IP {}."
        ).format(
            host,
            user,
            event.get("IpAddress", "UNKNOWN")
        )

    elif event_id == 4769:
        return (
            "Kerberos service ticket request detected on host {} "
            "for account {} requesting service {} from IP {}."
        ).format(
            host,
            user,
            event.get("ServiceName", "UNKNOWN"),
            event.get("IpAddress", "UNKNOWN")
        )

    elif event_id == 4770:
        return (
            "Kerberos service ticket renewal detected on host {} "
            "for account {}."
        ).format(
            host,
            user
        )

    elif event_id == 4771:
        return (
            "Kerberos pre-authentication failure detected on host {} "
            "for account {} from source IP {} with failure code {}."
        ).format(
            host,
            user,
            event.get("IpAddress", "UNKNOWN"),
            event.get("FailureCode", "UNKNOWN")
        )

    elif event_id == 4662:
        return (
            "Active Directory object access detected on domain controller {} "
            "initiated by account {} with operation type {} "
            "against object {}."
        ).format(
            host,
            user,
            event.get("OperationType", "UNKNOWN"),
            event.get("ObjectName", "UNKNOWN")
        )

    return "Windows authentication/security event detected."

def dictionary(event):
    FIELD_MAP = {
        # Common fields
        "event_id": "EventID",
        "host": "Hostname",
        "event_severity": "Severity",
        "event_type": "EventType",
        "source_account_name": "SubjectUserName",
        "source_account_domain": "SubjectDomainName",
        "source_logon_id":"SubjectLogonId",
        "source_ip": "IpAddress",

        # Kerberos fields (4768, 4769, 4770, 4771)
        "destination_account_domain": "TargetUserName",
        "service_name": "ServiceName",
        "ticket_encryption_type": "TicketEncryptionType",
        "ticket_options": "TicketOptions",
        "status": "Status",

        # Active Directory Object Access (4662)
        "object_server": "ObjectServer",
        "object_type": "ObjectType",
        "object_name": "ObjectName",
        "action_type": "OperationType",
        "access_mask_hex": "AccessMask",
        "access_list_raw": "AccessList",
        "access_reason_detail": "Properties",

        # Extra internal field
        "jumpserver": "jumpserver"
    }

    event_dict = {}

    for dest, src in FIELD_MAP.items():
        value = event.get(src)
        if value is None:
            continue

        if isinstance(value, basestring):  # Python 2.7
            value = value.strip()
            if value in ("", "-", "_", "UNKNOWN"):
                value = "UNKNOWN"
        event_dict[dest] = value
      
    if "event_id" in event_dict:
        event_dict["event_id"] = str(event_dict["event_id"])

    return event_dict



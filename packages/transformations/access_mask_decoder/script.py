def decode_access_mask_hex(hex_value):
    """
    Convert Windows AccessMask hex value (e.g., 0x120089) to human-readable access rights
    following Splunk CIM naming conventions -> access_rights
    """
    ACCESS_MASK_FLAGS = {
        0x1: "FILE_READ_DATA / FILE_LIST_DIRECTORY",
        0x2: "FILE_WRITE_DATA / FILE_ADD_FILE",
        0x4: "FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY",
        0x8: "FILE_READ_EA",
        0x10: "FILE_WRITE_EA",
        0x20: "FILE_EXECUTE / FILE_TRAVERSE",
        0x40: "FILE_DELETE_CHILD",
        0x80: "FILE_READ_ATTRIBUTES",
        0x100: "FILE_WRITE_ATTRIBUTES",
        0x10000: "DELETE",
        0x20000: "READ_CONTROL",
        0x40000: "WRITE_DAC",
        0x80000: "WRITE_OWNER",
        0x100000: "SYNCHRONIZE",
        0x1000000: "ACCESS_SYSTEM_SECURITY",
        0x2000000: "MAX_ALLOWED",
        0x10000000: "GENERIC_ALL",
        0x20000000: "GENERIC_EXECUTE",
        0x40000000: "GENERIC_WRITE",
        0x80000000: "GENERIC_READ"
    }

    try:
        mask = int(hex_value, 16)
    except Exception:
        return "unknown"

    permissions = []
    for bit, description in ACCESS_MASK_FLAGS.items():
        if mask & bit:
            permissions.append(description)

    if not permissions:
        return "unknown"

    return ", ".join(permissions)

def transform(event) :
    hex_val = event.get("access_mask_hex")
    if not hex_val:
        return event

    event["access_rights"] = decode_access_mask_hex(hex_val)

    return event  # Return the enriched event

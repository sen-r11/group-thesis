"""The event schema.

The parser writes one dict in this shape for every Sysmon record. A detector
reads that dict. It never reads the Sysmon XML, so a change to the parser does
not change a detector.

Two fields are always present:

    kind        always "host"
    time        a Unix timestamp in seconds

The parser adds "event_id", "pid" and "process" for every record. It adds the
other fields below when the record supplies them.
"""

HOST = "host"

KINDS = (HOST,)

# The Sysmon field name on the left. The schema field name on the right.
# The parser keeps these fields and discards the others.
FIELD_MAP = {
    "Image": "process",
    "ProcessId": "pid",
    "CommandLine": "cmdline",
    "ParentImage": "parent",
    "ParentProcessId": "ppid",
    "TargetFilename": "path",
    "DestinationIp": "dest",
    "DestinationPort": "port",
    "QueryName": "dns",
    "TargetImage": "target",
    "TargetObject": "registry",
    "Details": "detail",
    "ImageLoaded": "image",
}

# The Sysmon event IDs that the three malware families need.
EVENT_NAMES = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryAddDelete",
    13: "RegistrySetValue",
    15: "FileCreateStreamHash",
    22: "DnsQuery",
    23: "FileDelete",
    25: "ProcessTampering",
}

# The fields that every event holds, whatever the event ID was.
ALWAYS = ("kind", "time", "event_id", "pid", "process")


def name_of(event_id):
    """Return the Sysmon name for an event ID."""
    return EVENT_NAMES.get(event_id, "Event %d" % event_id)


def subject(event):
    """Return a short name for the thing that caused the event."""
    return event.get("process", "unknown")


def extras(event):
    """Return the fields that the event ID added, in name order."""
    return sorted(key for key in event if key not in ALWAYS)

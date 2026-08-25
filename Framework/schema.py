# The event schema: the shape the parser writes for every Sysmon record

# Every event holds "kind" and "time", plus "event_id", "pid" and "process".
# It holds the other fields below when the record supplies them.

HOST = "host"

KINDS = (HOST,)

# The Sysmon field name on the left, the schema field name on the right.
# The parser keeps these and discards the others.
FIELD_MAP = {
    "Image": "process",
    "ProcessId": "pid",
    # Events 8 and 10 name the acting process differently
    "SourceImage": "process",
    "SourceProcessId": "pid",
    "TargetProcessId": "target_pid",
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
    "PipeName": "pipe",
    "GrantedAccess": "granted_access",
}

# The Sysmon event IDs that the three malware families need
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
    17: "PipeCreated",
    18: "PipeConnected",
    22: "DnsQuery",
    23: "FileDelete",
    25: "ProcessTampering",
}

# The fields every event holds, whatever the event ID was
ALWAYS = ("kind", "time", "event_id", "pid", "process")


def name_of(event_id):
    return EVENT_NAMES.get(event_id, "Event %d" % event_id)


def subject(event):
    return event.get("process", "unknown")


def extras(event):
    return sorted(key for key in event if key not in ALWAYS)

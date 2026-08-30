from Detection.indicators.base import Finding


"""detects a process that is running from a user writable location such as AppData,
TEmp or Downloads, and creates a number of files from there."""

"""" noraml, trusted programs run from the following locations, if a process runs from anywhere else that is a suspicious behaviour"""
TRUSTED_PREFIXES = (
    "C:\\PROGRAM FILES",
    "C:\\PROGRAM FILES (X86)",
    "C:\\WINDOWS",
    "E:\\PROGRAM FILES",
    "E:\\PROGRAM FILES (X86)",
)



""""user writable locations taht malware commonly runs from"""
USER_WRITABLE_MARKERS = (
    "\\APPDATA\\",
    "LOCAL\\TEMP\\",
    "\\DOWNLOADS\\",
    "\\PUBLIC\\",
)


"""how many file creation events from an untrusted location process before its treated as a suspicious/staging behaviour"""
FILE_CREATE_THRESHOLD = 5

def isUntrustedLocation(path):
    if not path:
        return False
    upper = path.upper()
    # if it starts with a trusted prefix its fien
    for prefix in TRUSTED_PREFIXES:
        if upper.startswith(prefix):
            return False
    #if its in a user writable area its suspicious
    for marker in USER_WRITABLE_MARKERS:
        if marker in upper:
            return True
    return False


""""produces a finding if an untrusted location process stages many files"""
#count file creation evetns per process running from an untrusted location
def detect(events, state):
    counts = {}
    evidence = {}

    for event in events:
        if event.get("event_id") != 11:
            continue

        pid = event.get("pid")
        counts[pid] = counts.get(pid, 0) + 1
        evidence.setdefault(pid, []).append(event)


    #trigger for any process that crossed the staging threshold
    for pid, count in counts.items():
        if count >= FILE_CREATE_THRESHOLD:
            hit_events = evidence[pid]
            process = hit_events[0].get("process", "unknown")
            yield Finding(
                Fingerprint=f"spyware_staging: {pid}",
                description=("Process running from a user writable location created multiple files, similar to malware staging behaviour"
                ),
                weights={"spyware": 0.3, "rat": 0.1, "ransomware": 0.1},
                severity="medium",
                events="hit_events",
            )
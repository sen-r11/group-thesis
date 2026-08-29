# Detects a program in a user-writable location filling a folder under AppData

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

# Installed software writes here too, but a handful of files at a time. The
# count is what separates saving settings from unpacking a payload
DROP_THRESHOLD = 25

TARGET = "\\appdata\\roaming\\"


def _counts(store):
    table = getattr(store, "staging_drops", None)
    if table is None:
        table = {}
        store.staging_drops = table
    return table


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 11 records file creation
    if int(event.get("event_id") or 0) != 11:
        return []

    process = str(event.get("process") or "")
    if not any(place in process.lower().replace("/", "\\") for place in USER_WRITABLE):
        return []

    path = str(event.get("path") or "").replace("/", "\\").lower()
    if TARGET not in path:
        return []

    # Counted against the file on disk, not the pid. Malware restarts itself,
    # and a count kept per pid starts again every time it does
    table = _counts(store)
    key = process.lower()
    table[key] = table.get(key, 0) + 1
    if table[key] != DROP_THRESHOLD:
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="staging_drop",
            description="Program in a user-writable location wrote many files into AppData",
            weights={
                "ransomware": 0.20,
                "spyware": 0.25,
                "rat": 0.15,
            },
            fingerprint=f"staging_drop:{root_pid}:{key}",
            score_key=f"staging_drop:{root_pid}",
            details={
                "process": process,
                "files_written": table[key],
                "path": event.get("path", ""),
            },
            target_pid=root_pid,
        )
    ]

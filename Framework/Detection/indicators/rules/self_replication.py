# Detects a program in a user-writable location starting copies of itself

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


def process_name(path: str) -> str:
    return str(path or "").replace("/", "\\").lower().split("\\")[-1]


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 1 records process creation
    if int(event.get("event_id") or 0) != 1:
        return []

    child = str(event.get("process") or "")
    parent = str(event.get("parent") or "")
    if not child or not parent:
        return []

    if process_name(child) != process_name(parent):
        return []

    # A browser starts copies of itself for every tab, and an updater does the
    # same. Where the program sits is what separates that from staging
    if not any(place in child.lower().replace("/", "\\") for place in USER_WRITABLE):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="self_replication",
            description="Program in a user-writable location started another copy of itself",
            weights={
                "ransomware": 0.15,
                "spyware": 0.30,
                "rat": 0.25,
            },
            fingerprint=f"self_replication:{root_pid}:{process_name(child)}",
            score_key=f"self_replication:{root_pid}",
            details={
                "process": child,
                "parent": parent,
                "command_line": event.get("cmdline", ""),
            },
            target_pid=root_pid,
        )
    ]

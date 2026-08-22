# Detects bursts of file deletions

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

WINDOW_SECONDS = 10.0
DELETE_EVENT_THRESHOLD = 4

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    #Event 23 records file deletion
    if int(event.get("event_id") or 0) != 23:
        return []
    
    now = float(event.get("time") or 0.0)
    recent_deletions = [
        item
        for item in direct_state.file_events
        if item[1] == 23 and now - item[0] <= WINDOW_SECONDS
    ]

    if len(recent_deletions) < DELETE_EVENT_THRESHOLD:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="file_deletion_burst",
            description="Process deleted multiple files within a short time period",
            weights={
                "ransomware": 0.20,
            },
            fingerprint=f"file_deletion:{root_pid}",
            details={
                "deletion_count": len(recent_deletions),
                "window_seconds": WINDOW_SECONDS,
                "process": event.get("process", ""),
            },
            target_pid=root_pid,
        )
    ]
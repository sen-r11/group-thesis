# Detects unusually high file activity

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

WINDOW_SECONDS = 10.0
FILE_EVENT_THRESHOLD = 5

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Only file creation and deletion events are relevant
    if int(event.get("event_id") or 0) not in (11, 23):
        return []
    
    now = float(event.get("time") or 0.0)
    recent_events = [
        item
        for item in direct_state.file_events
        if now - item[0] <= WINDOW_SECONDS
    ]
    
    if len(recent_events) < FILE_EVENT_THRESHOLD:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="rapid_file_activity",
            description="Process performed a large number of file operations in a short time period",
            weights={
                "ransomware": 0.30,
            },
            fingerprint=f"rapid_files:{root_pid}",
            details={
                "event_count": len(recent_events),
                "window_seconds": WINDOW_SECONDS,
                "process": event.get("process", ""),
            },
            target_pid=root_pid,
        )
    ]
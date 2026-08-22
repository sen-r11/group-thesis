# Handles Sysmon ProcessTampering events

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # event 25 records process tampering
    if int(event.get("event_id") or 0) != 25:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="process_tampering",
            description="Sysmon detected process tampering activity",
            weights={
                "ransomware": 0.10,
                "spyware": 0.25,
                "rat": 0.30,
            },
            fingerprint=f"process_tampering:{root_pid}",
            details={
                "process": event.get("process", ""),
                "target": event.get("target", ""),
            },
            target_pid=root_pid,
        )
    ]
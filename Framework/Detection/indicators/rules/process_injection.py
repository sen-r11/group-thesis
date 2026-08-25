# Detects CreateRemoteThread / suspicious ProcessAccess activity


from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    event_id = int(event.get("event_id") or 0)
    # only CreateRemoteThread and ProcessAccess events are relevant
    if event_id not in (8, 10):
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    target = str(event.get("target") or "")

    if event_id == 8:
        return [
            Finding(
                indicator="create_remote_thread",
                description="Process created a remote thread inside another process",
                weights={
                    "ransomware": 0.10,
                    "spyware": 0.30,
                    "rat": 0.35,
                },
                fingerprint=f"remote_thread:{root_pid}",
                details={
                    "process": event.get("process", ""),
                    "target": target,
                },
                target_pid=root_pid,
            )
        ]
    
    if event_id == 10:
        return [
            Finding(
                indicator="process_access",
                description="Process accessed another process",
                weights={
                    "spyware": 0.10,
                    "rat": 0.15,
                },
                fingerprint=f"process_access:{root_pid}",
                details={
                    "process": event.get("process", ""),
                    "target": target,
                },
                target_pid=root_pid,
            )
        ]
    return []
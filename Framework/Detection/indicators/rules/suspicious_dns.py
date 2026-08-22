# Checks DNS activity that becomes suspicious in context

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore


SUSPICIOUS_LOCATIONS = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
)

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 22 records DNS queries
    if int(event.get("event_id") or 0) != 22:
        return []
    
    process = str(event.get("process") or "").lower()
    dns = str(event.get("dns") or "").lower()

    if not dns:
        return []
    
    suspicious_location = any(
        location in process
        for location in SUSPICIOUS_LOCATIONS
    )
    if not suspicious_location:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="suspicious_dns",
            description="Process running from a user-writable location performed a DNS query",
            weights={
                "ransomware": 0.05,
                "spyware": 0.10,
                "rat": 0.15,
            },
            fingerprint=f"suspicious_dns:{root_pid}",
            details={
                "process": event.get("process", ""),
                "dns": event.get("dns", ""),
            },
            target_pid=root_pid,
        )
    ]
# Checks suspicious outbound network behaviour

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore


SUSPICIOUS_LOCATIONS = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
)

COMMON_PORTS = (
    53,
    80,
    443,
)

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 3 records network connections
    if int(event.get("event_id") or 0) != 3:
        return []
    
    process = str(event.get("process") or "").lower()
    destination = str(event.get("dest") or "")
    port_value = event.get("port")
    
    if not destination:
        return []
    
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        return []
    
    suspicious_location = any(
        location in process
        for location in SUSPICIOUS_LOCATIONS
    )

    unusual_port = port not in COMMON_PORTS

    if not suspicious_location or not unusual_port:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="suspicious_network_connection",
            description="Process running from a user-writable location made a network connection over an uncommon port",
            weights={
                "ransomware": 0.05,
                "spyware": 0.15,
                "rat": 0.20,
            },
            fingerprint=f"suspicious_network:{root_pid}:{destination}:{port}",
            score_key=f"suspicious_network:{root_pid}",
            details={
                "process": event.get("process", ""),
                "destination": destination,
                "port": port,
            },
            target_pid=root_pid,
        )
    ]
    

                  
    
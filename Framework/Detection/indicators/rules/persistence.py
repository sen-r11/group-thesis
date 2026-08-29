# Detects registry-based persistence

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore


PERSISTENCE_KEYS = (
    "\\software\\microsoft\\windows\\currentversion\\run",
    "\\software\\microsoft\\windows\\currentversion\\runonce",
    "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell",
    "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\userinit",
)

SERVICE_ROOT = "\\system\\currentcontrolset\\services\\"

SERVICE_PERSISTENCE_VALUES = (
    "\\imagepath",
    "\\start",
    "\\parameters\\servicedll",
)

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 13 records a registry value being changed
    if int(event.get("event_id") or 0) != 13:
        return []
    
    registry = str(event.get("registry") or "").lower()
    if not registry:
        return []
    
    matched = any(key in registry for key in PERSISTENCE_KEYS)
    if not matched:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="registry_persistence",
            description="Process modified a registry location commonly used for persistence",
            weights={
                "ransomware": 0.10,
                "spyware": 0.25,
                "rat": 0.25,
            },
            fingerprint=f"persistence:{root_pid}:{registry}",
            score_key=f"persistence:{root_pid}",
            details={
                "registry": event.get("registry", ""),
                "detail": event.get("detail", ""),
            },
            target_pid=root_pid,
        )
    ]
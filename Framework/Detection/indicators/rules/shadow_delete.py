# Detects shadow copy deletion commands

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # shadow copy deletion should appear through a process creation event
    if int(event.get("event_id") or 0) != 1:
        return []
    
    process = str(event.get("process") or "").lower()
    cmdline = str(event.get("cmdline") or "").lower()

    matched = (
        ("vssadmin.exe" in process and "delete shadows" in cmdline)
        or ("wmic.exe" in process and "shadowcopy" in cmdline and "delete" in cmdline)
        or ("powershell" in process and "win32_shadowcopy" in cmdline and "delete" in cmdline)
    )
    
    if not matched:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="shadow_copy_deletion",
            description="Process attempted to delete Windows shadow copies",
            weights={"ransomware": 0.40},
            fingerprint=f"shadow_delete:{root_pid}",
            details={
                "process": event.get("process", ""),
                "command_line": event.get("cmdline", ""),
            },
            target_pid=root_pid,
        )
    ]

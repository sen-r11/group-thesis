# Checks unusual process relationships

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore


SUSPICIOUS_PARENTS = (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
)

SUSPICIOUS_CHILDREN = (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
)

def process_name(path: str) -> str:
    path = path.replace("/", "\\").lower()
    return path.split("\\")[-1]

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 1 records process creation
    if int(event.get("event_id") or 0) != 1:
        return []
    
    child = process_name(str(event.get("process") or ""))
    parent = process_name(str(event.get("parent") or ""))

    if not child or not parent:
        return []
    if parent not in SUSPICIOUS_PARENTS:
        return []
    if child not in SUSPICIOUS_CHILDREN:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="unusual_parent_child",
            description="Process was launched from an unusual parent-child relationship",
            weights={
                "ransomware": 0.10,
                "spyware": 0.15,
                "rat": 0.20,
            },
            fingerprint=f"parent_child:{root_pid}:{parent}:{child}",
            details={
                "parent": event.get("parent", ""),
                "process": event.get("process", ""),
                "cmdline": event.get("cmdline", ""),
            },
            target_pid=root_pid,
        )
    ]
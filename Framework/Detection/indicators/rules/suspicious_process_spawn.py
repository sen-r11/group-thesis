# Detects suspicious child-process execution


from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore


SUSPICIOUS_PROCESSES = (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "vssadmin.exe",
    "wmic.exe",
)

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 1 records process creation
    if int(event.get("event_id") or 0) != 1:
        return []
    
    process = str(event.get("process") or "").lower()

    matched_process = None
    for name in SUSPICIOUS_PROCESSES:
        if process.endswith(name):
            matched_process = name
            break
    
    if matched_process is None:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="suspicious_process_spawn",
            description="Process launched a potentially suspicious child process",
            weights={
                "ransomware": 0.15,
                "spyware": 0.10,
                "rat": 0.20,
            },
            fingerprint=f"suspicious_spawn:{root_pid}:{matched_process}",
            score_key=f"suspicious_spawn:{root_pid}",
            details={
                "process": event.get("process", ""),
                "parent": event.get("parent", ""),
                "command_line": event.get("cmdline", ""),
            },
            target_pid=root_pid,
        )
    ]
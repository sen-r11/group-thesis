# Detects suspicious file extensions

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

SUSPICIOUS_EXTENSIONS = (
    ".locked",
    ".encrypted",
    ".crypted",
    ".crypt",
    ".enc",
)

def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # event 11 records file creation
    if int(event.get("event_id") or 0) != 11:
        return []
    
    path = str(event.get("path") or "").lower()
    if not path:
        return []
    
    matched_extension = None
    
    for extension in SUSPICIOUS_EXTENSIONS:
        if path.endswith(extension):
            matched_extension = extension
            break
    if matched_extension is None:
        return []
    
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="suspicious_file_extension",
            description="Process created a file with a suspicious ransomware-style extension",
            weights={
                "ransomware": 0.25,
            },
            fingerprint=f"suspicious_extension:{root_pid}:{path}",
            score_key=f"suspicious_extension:{root_pid}",
            details={
                "path": event.get("path", ""),
                "extension": matched_extension,
            },
            target_pid=root_pid,
        )
    ]
# Detects spyware-oriented browser and credential collection behaviour

from typing import List
from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

# Malware executing from one of these locations is more suspicious than ordinary installed software accessing browser-related data
USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

# Browser processes that may contain credentials, cookies or active sessions
BROWSER_PROCESSES = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
)

# Common browser/credential data store. Event 11 cannot prove that the original data was read, so this rule only reports that a suspicious process created an artifact with a credential-related name
CREDENTIAL_ARTIFACTS = (
    "login data",
    "web data",
    "cookies",
    "cookies.sqlite",
    "logins.json",
    "key4.db",
    "local state",
    "wallet.dat",
)

# Windows process-access rights
PROCESS_VM_READ = 0x0010

# Rights already handled by privileged_process_access. Excluding them here avoids interpreting the same injection-style access twice
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020

INJECTION_RIGHTS = (
    PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_WRITE
)

def process_name(path: str) -> str:
    return str(path or "").replace("/", "\\").lower().split("\\")[-1]

def parse_access(value) -> int:
    if isinstance(value, int):
        return value

    text = str(value or "").strip().lower()
    if not text:
        return 0

    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return 0

def suspicious_source(path: str) -> bool:
    value = str(path or "").replace("/", "\\").lower()

    if not any(location in value for location in USER_WRITABLE):
        return False

    if process_name(value) in BROWSER_PROCESSES:
        return False
    return True

def credential_artifact(path: str):
    name = process_name(path)

    for artifact in CREDENTIAL_ARTIFACTS:
        if name == artifact:
            return artifact

        if name.startswith(artifact + "-"):
            return artifact

    return None

def detect(
        event: dict,
        store: StateStore,
        direct_state: ProcessState
        ) -> List[Finding]:

    event_id = int(event.get("event_id") or 0)
    process = str(event.get("process") or "")

    if not suspicious_source(process):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid

    if event_id == 11:
        path = str(event.get("path") or "")
        matched = credential_artifact(path)

        if matched is None:
            return []

        return [
            Finding(
                indicator="credential_collection",
                description=(
                    "Process created an artifact associated with browser or credential data"
                    ),
                    weights={
                        "spyware": 0.30,
                        "rat": 0.10,
                    },
                    fingerprint=f"credential_file:{root_pid}:{path.lower()}",
                    score_key=f"credential_collection:{root_pid}",
                    details={
                        "process": process,
                        "path": path,
                        "matched_artifact": matched,
                        "method": "credential_artifact_creation",
                    },
                    target_pid=root_pid,
            )
        ]


    if event_id == 10:
            target = str(event.get("target") or "")
            target_name = process_name(target)
    
            if target_name not in BROWSER_PROCESSES:
                return []

            access = parse_access(event.get("granted_access"))

            if not access & PROCESS_VM_READ:
                return []

            if access & INJECTION_RIGHTS:
                return []
            
            return [
                Finding(
                    indicator="credential_collection",
                    description=(
                        "Suspicious process accessed browser process memory with read permissions"
                        ),
                        weights={
                            "spyware": 0.30,
                            "rat": 0.10,
                        },
                        fingerprint=f"browser_memory_read:{root_pid}:{target.lower()}",
                        score_key=f"credential_collection:{root_pid}",
                        details={
                            "process": process,
                            "target": target,
                            "granted_access": event.get("granted_access", ""),
                            "method": "browser_process_memory_read",
                        },
                        target_pid=root_pid,
                )
            ]

    return []

    
    
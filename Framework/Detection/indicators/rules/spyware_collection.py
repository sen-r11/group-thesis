# Detects spyware-oriented browser and credential collection behaviour

import ipaddress
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

STAGING_LOCATIONS = (
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

STAGING_FILE_THRESHOLD = 10

RUNTIME_STAGING_EXTENSIONS = (
    ".dll",
    ".pyd",
    ".sys",
    ".ocx",
    ".pyc",
    ".zip",
)

RUNTIME_STAGING_MARKERS = (
    "\\_mei",
)

RANSOM_NOTE_TERMS = (
    "readme_decrypt",
    "how_to_decrypt",
    "how-to-decrypt",
    "decrypt_instructions",
    "ransom_note",
    "restore_files",
    "recover_files",
)

BENIGN_BROWSER_ACCESS_SOURCES = (
    "\\appdata\\local\\microsoft\\onedrive\\onedrive.exe",
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

def normalise_path(path: str) -> str:
    return str(path or "").replace("/", "\\").lower()

def valid_staging_file(path: str) -> bool:
    value = normalise_path(path)

    if not any(location in value for location in STAGING_LOCATIONS):
        return False

    if any(marker in value for marker in RUNTIME_STAGING_MARKERS):
        return False

    if value.endswith(RUNTIME_STAGING_EXTENSIONS):
        return False

    name = value.split("\\")[-1]

    if any(term in name for term in RANSOM_NOTE_TERMS):
        return False

    return True

def process_name(path: str) -> str:
    return normalise_path(path).split("\\")[-1]

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

def benign_browser_access_source(path: str) -> bool:
    value = str(path or "").replace("/", "\\").lower()

    return any(
        value.endswith(trusted_path)
        for trusted_path in BENIGN_BROWSER_ACCESS_SOURCES
    )

def credential_artifact(path: str):
    name = process_name(path)

    for artifact in CREDENTIAL_ARTIFACTS:
        if name == artifact:
            return artifact

        if name.startswith(artifact + "-"):
            return artifact

    return None

def public_destination(value) -> bool:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )

def same_image_chain(
        store: StateStore,
        direct_state: ProcessState
        ) -> List[ProcessState]:

    chain = [direct_state]
    current = direct_state
    image = normalise_path(direct_state.process)
    seen = {direct_state.pid}

    for _ in range(store.MAX_HOPS):
        if not current.ppid or current.ppid in seen:
            break

        parent = store.get(current.ppid)
        if parent is None:
            break

        if normalise_path(parent.process) != image:
            break

        chain.append(parent)
        seen.add(parent.pid)
        current = parent

    return chain


def recent_staged_files(
        event_time: float,
        chain: List[ProcessState],
        history_seconds: float
        ) -> List[str]:

    staged = set()

    for state in chain:
        for timestamp, event_id, path in state.file_events:
            age = event_time - float(timestamp)

            if event_id != 11:
                continue

            if age < 0 or age > history_seconds:
                continue

            value = normalise_path(path)

            if valid_staging_file(value):
                staged.add(value)

    return sorted(staged)

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
    if event_id == 3:
        destination = str(event.get("dest") or "")

        if not public_destination(destination):
            return []

        chain = same_image_chain(store, direct_state)

        if len(chain) < 2:
            return []

        staged_files = recent_staged_files(
            float(event.get("time") or 0.0),
            chain,
            store.HISTORY_SECONDS,
        )

        if len(staged_files) < STAGING_FILE_THRESHOLD:
            return []

        return [
            Finding(
                indicator="collection_staging_network",
                description=(
                    "Self-spawning process chain staged multiple files in "
                    "user-writable locations before outbound communication"
                ),
                weights={
                    "spyware": 0.60,
                    "rat": 0.10,
                },
                fingerprint=(
                    f"collection_staging_network:{root_pid}:"
                    f"{destination.lower()}:{event.get('port', '')}"
                ),
                score_key=f"collection_staging_network:{root_pid}",
                details={
                    "process": process,
                    "destination": destination,
                    "port": event.get("port", ""),
                    "staged_file_count": len(staged_files),
                    "staged_files": staged_files[:10],
                    "chain_pids": [state.pid for state in chain],
                    "method": "staging_followed_by_outbound_network",
                },
                target_pid=root_pid,
            )
        ]


    if event_id == 10:
        target = str(event.get("target") or "")
        target_name = process_name(target)
        if target_name not in BROWSER_PROCESSES:
            return []
        if benign_browser_access_source(process):
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

    
    
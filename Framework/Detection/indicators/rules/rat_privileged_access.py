# Detects process access asking for the rights needed to inject code

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

# Windows process access rights
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020

INJECTION_RIGHTS = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE

# Windows opens processes with full rights as part of its normal work, so
# only a process running from one of these is reported
USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

RIGHT_NAMES = (
    (PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"),
    (PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"),
    (PROCESS_VM_WRITE, "PROCESS_VM_WRITE"),
)


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


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 10 records one process opening another
    if int(event.get("event_id") or 0) != 10:
        return []

    access = parse_access(event.get("granted_access"))
    if not access & INJECTION_RIGHTS:
        return []

    process = str(event.get("process") or "").lower()
    if not any(location in process for location in USER_WRITABLE):
        return []

    target = str(event.get("target") or "")
    if target and target.lower() == process:
        return []

    target_pid = event.get("target_pid")

    if isinstance(target_pid, str) and target_pid.isdigit():
        target_pid = int(target_pid)

    if isinstance(target_pid, int):
            target_state = store.get(target_pid)

            if target_state is not None and target_state.ppid == direct_state.pid:
                return []

    rights = [name for bit, name in RIGHT_NAMES if access & bit]
    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="privileged_process_access",
            description="Process opened another process with the rights needed to write into it",
            weights={
                "spyware": 0.25,
                "rat": 0.30,
            },
            fingerprint=f"privileged_access:{root_pid}:{target}",
            score_key=f"privileged_access:{root_pid}",
            details={
                "process": event.get("process", ""),
                "target": target,
                "granted_access": event.get("granted_access", ""),
                "rights": ", ".join(rights),
            },
            target_pid=root_pid,
        )
    ]

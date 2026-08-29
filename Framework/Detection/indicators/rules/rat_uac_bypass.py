# Detects malware getting full rights without asking the user

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore, process_name

USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

# Windows starts these with full rights and shows no prompt. Malware points
# one of them at itself, so the child it starts is elevated too
AUTO_ELEVATING = {
    "fodhelper.exe",
    "computerdefaults.exe",
    "sdclt.exe",
    "eventvwr.exe",
    "cmstp.exe",
    "wsreset.exe",
    "slui.exe",
    "dccw.exe",
}

# The command one of those binaries reads when it starts. The copy under the
# user's own hive is read first and needs no rights to write, so writing one
# is how the binary is pointed somewhere else
HIJACKED_COMMANDS = (
    "ms-settings\\shell\\open\\command",
    "folder\\shell\\open\\command",
    "exefile\\shell\\open\\command",
    "mscfile\\shell\\open\\command",
)


def user_writable(path: str) -> bool:
    low = str(path or "").lower()
    return any(place in low for place in USER_WRITABLE)


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    event_id = int(event.get("event_id") or 0)
    root_pid = store.attribution_state(direct_state.pid).pid

    # Event 13 records a value being written to the registry
    if event_id == 13:
        key = str(event.get("registry") or "").lower()
        if not any(command in key for command in HIJACKED_COMMANDS):
            return []

        # Only the user's own hive matters. The machine-wide copy already
        # needs the rights the malware is trying to get
        if "hku\\" not in key and "hkcu" not in key:
            return []

        return [
            Finding(
                indicator="uac_bypass_setup",
                description="Process redirected a command that Windows runs with full rights",
                weights={
                    "ransomware": 0.15,
                    "spyware": 0.30,
                    "rat": 0.45,
                },
                fingerprint=f"uac_setup:{root_pid}:{key[:80]}",
                score_key=f"uac_setup:{root_pid}",
                details={
                    "process": event.get("process", ""),
                    "registry": event.get("registry", ""),
                    "value": event.get("detail", ""),
                },
                target_pid=root_pid,
            )
        ]

    # Event 1 records process creation
    if event_id != 1:
        return []

    parent = process_name(event.get("parent"))
    if parent not in AUTO_ELEVATING:
        return []

    # Windows starts these itself as well, so the child having been written
    # somewhere the user can write is what separates the two cases
    child = str(event.get("process") or "")
    if not user_writable(child):
        return []

    return [
        Finding(
            indicator="uac_bypass_launch",
            description="A Windows binary that elevates without a prompt started a process from a user-writable location",
            weights={
                "ransomware": 0.15,
                "spyware": 0.30,
                "rat": 0.45,
            },
            fingerprint=f"uac_launch:{root_pid}:{child.lower()[:80]}",
            score_key=f"uac_launch:{root_pid}",
            details={
                "process": child,
                "parent": event.get("parent", ""),
                "command_line": event.get("cmdline", ""),
            },
            target_pid=root_pid,
        )
    ]

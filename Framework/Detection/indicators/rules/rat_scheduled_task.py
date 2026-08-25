# Detects persistence created through a scheduled task or a service

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

# The tool, and the command line word that means a new one is being made.
# Listing a task is not persistence, so the word matters.
PERSISTENCE_TOOLS = {
    "schtasks.exe": ("/create", "-create"),
    "at.exe": ("",),
    "sc.exe": ("create", "config"),
    "powershell.exe": ("register-scheduledtask", "new-scheduledtask"),
    "pwsh.exe": ("register-scheduledtask", "new-scheduledtask"),
}


def process_name(path: str) -> str:
    return str(path or "").replace("/", "\\").lower().split("\\")[-1]


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 1 records process creation
    if int(event.get("event_id") or 0) != 1:
        return []

    name = process_name(event.get("process"))
    keywords = PERSISTENCE_TOOLS.get(name)
    if keywords is None:
        return []

    cmdline = str(event.get("cmdline") or "").lower()
    if not any(keyword in cmdline for keyword in keywords):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="scheduled_task_persistence",
            description="Process created a scheduled task or a service, which survives a restart",
            weights={
                "ransomware": 0.10,
                "spyware": 0.20,
                "rat": 0.25,
            },
            fingerprint=f"scheduled_task:{root_pid}:{name}",
            score_key=f"scheduled_task:{root_pid}",
            details={
                "process": event.get("process", ""),
                "parent": event.get("parent", ""),
                "command_line": event.get("cmdline", ""),
                "tool": name,
            },
            target_pid=root_pid,
        )
    ]

# Detects a network-active process running a one-shot shell command

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

NETWORK_WINDOW = 300.0

# The shell, and the command line words that mean it runs one command and
# exits. A person opening a terminal starts a shell with no command.
SHELLS = {
    "cmd.exe": ("/c",),
    "powershell.exe": ("-command", "-c ", "-enc", "-encodedcommand"),
    "pwsh.exe": ("-command", "-c ", "-enc", "-encodedcommand"),
    "wscript.exe": ("",),
    "cscript.exe": ("",),
    "mshta.exe": ("",),
}

OPERATOR_COMMANDS = (
    "whoami",
    "ipconfig",
    "systeminfo",
    "net user",
    "net group",
    "nltest",
    "netstat",
    "tasklist",
    "query user",
    "arp -a",
    "route print",
)


def process_name(path: str) -> str:
    return str(path or "").replace("/", "\\").lower().split("\\")[-1]


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 1 records process creation
    if int(event.get("event_id") or 0) != 1:
        return []

    child = process_name(event.get("process"))
    keywords = SHELLS.get(child)
    if keywords is None:
        return []

    cmdline = str(event.get("cmdline") or "").lower()
    if not any(keyword in cmdline for keyword in keywords):
        return []

    encoded = "-enc" in cmdline or "-encodedcommand" in cmdline
    operator_command = any(command in cmdline for command in OPERATOR_COMMANDS)
    if not encoded and not operator_command:
        return []

    ppid = event.get("ppid")
    if isinstance(ppid, str) and ppid.isdigit():
        ppid = int(ppid)
    if not isinstance(ppid, int):
        return []

    parent = store.get(ppid)
    if parent is None:
        return []

    now = float(event.get("time") or 0.0)
    recent = [entry for entry in parent.network_events
              if now - entry[0] <= NETWORK_WINDOW]
    if not recent:
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="remote_command_execution",
            description="Network-active process ran a one-shot shell command",
            weights={
                "spyware": 0.10,
                "rat": 0.40,
            },
            fingerprint=f"remote_shell:{root_pid}:{child}:{cmdline[:80]}",
            score_key=f"remote_shell:{root_pid}",
            details={
                "parent": parent.process,
                "shell": child,
                "command_line": event.get("cmdline", ""),
                "encoded": "-enc" in cmdline,
                "parent_network_events": len(recent),
                "last_destination": recent[-1][2],
            },
            target_pid=root_pid,
        )
    ]

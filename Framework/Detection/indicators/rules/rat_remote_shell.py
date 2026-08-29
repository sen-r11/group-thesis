# Detects a network-active process running a one-shot shell command

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

NETWORK_WINDOW = 300.0

# Commands that switch protection off or destroy the copies a machine is
# restored from. Ransomware runs a long burst of these before it encrypts,
# so they say more about the family than about a remote operator
DESTRUCTIVE = (
    "taskkill",
    "sc stop",
    "sc delete",
    "sc config",
    "net stop",
    "vssadmin",
    "wbadmin",
    "bcdedit",
    "shadowcopy",
    "shadowstorage",
    "mpcmdrun",
    "wevtutil cl",
)

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
    destructive = any(word in cmdline for word in DESTRUCTIVE)

    if destructive:
        indicator = "defence_evasion_command"
        description = "Process ran a shell command that turns off protection or destroys recovery data"
        weights = {"ransomware": 0.30, "spyware": 0.05, "rat": 0.05}
    else:
        indicator = "remote_command_execution"
        description = "Network-active process ran a one-shot shell command"
        weights = {"spyware": 0.10, "rat": 0.40}

    return [
        Finding(
            indicator=indicator,
            description=description,
            weights=weights,
            fingerprint=f"remote_shell:{root_pid}:{child}:{cmdline[:80]}",
            score_key=f"remote_shell:{indicator}:{root_pid}",
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

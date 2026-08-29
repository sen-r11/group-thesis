# Handles process state, PID/PPID relationships, event history, 
# triggered indicators and family scores.

from dataclasses import dataclass, field
from collections import deque
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple

FAMILIES = ("ransomware", "spyware", "rat")


def process_name(path: str) -> str:
    return str(path or "").replace("/", "\\").lower().split("\\")[-1]


@dataclass
class Evidence:
    indicator: str
    description: str
    time: float
    event_id: int
    process: str
    details: Dict[str, object] = field(default_factory=dict)
    weights: Dict[str, object] = field(default_factory=dict)

@dataclass
class ProcessState:
    pid: int
    process: str = "unknown"
    ppid: Optional[int] = None
    parent: str = ""
    command_line: str = ""
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    file_events: Deque[Tuple[float, int, str]] = field(default_factory=deque)
    network_events: Deque[Tuple[float, int, str, object]] = field(default_factory=deque)
    registry_events: Deque[Tuple[float, int, str, str]] = field(default_factory=deque)

    family_scores: Dict[str, float] = field(default_factory=lambda: {family: 0.0 for family in FAMILIES})
    evidence: List[Evidence] = field(default_factory=list)
    fired: Set[str] = field(default_factory=set)
    scored: Set[str] = field(default_factory=set)

    def add_scores(self, weights: Dict[str, float]) -> None:
        for family, weight in weights.items():
            if family in self.family_scores:
                self.family_scores[family] += float(weight)

    def best_family(self) -> Tuple[str, float]:
        family = max(self.family_scores, key=self.family_scores.get)
        return family, self.family_scores[family]

class StateStore:
    #keeps process history so seperate events can be correlated

    HISTORY_SECONDS = 60.0

    # Utilities malware drives to do its work. What one of these does belongs
    # to whatever launched it, not to the utility
    HELPERS = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "conhost.exe",
        "taskkill.exe", "net.exe", "net1.exe", "sc.exe", "reg.exe",
        "schtasks.exe", "vssadmin.exe", "wmic.exe", "bitsadmin.exe",
        "certutil.exe", "attrib.exe", "icacls.exe", "wevtutil.exe",
    }

    # Windows starts nearly everything from these, so a finding that moved into
    # one would put the whole machine under a single process
    LAUNCHERS = {
        "explorer.exe", "services.exe", "svchost.exe", "winlogon.exe",
        "wininit.exe", "userinit.exe", "runtimebroker.exe", "system",
    }

    MAX_HOPS = 4

    def __init__(self) -> None:
        self.processes: Dict[int, ProcessState] = {}

    def get(self, pid: int) -> Optional[ProcessState]: 
        return self.processes.get(pid)
    
    def ensure(self, pid: int, process: str = "unknown") -> ProcessState: 
        state = self.processes.get(pid)
        if state is None:
            state = ProcessState(pid=pid, process=process or "unknown")
            self.processes[pid] = state
        elif process and process != "unknown":
            state.process = process
        return state
    
    def observe(self, event: Dict[str,object]) -> ProcessState:
        pid = int(event.get("pid") or 0)
        process = str(event.get("process") or "unknown")

        # Windows gives a PID back out once the process using it ends, so a
        # process start always begins a new record. Without this a new process
        # inherits the history and the scores of the dead one that had its PID
        if int(event.get("event_id") or 0) == 1:
            self.processes.pop(pid, None)

        state = self.ensure(pid, process)

        now = float(event.get("time") or 0.0)
        if state.first_seen is None:
            state.first_seen = now
        state.last_seen = now

        if event.get("cmdline"):
            state.command_line = str(event["cmdline"])

        ppid = event.get("ppid")
        if isinstance(ppid, int):
            state.ppid = ppid
        elif isinstance(ppid, str) and ppid.isdigit():
            state.ppid = int(ppid)

        if event.get("parent"):
            state.parent = str(event["parent"])

        event_id = int(event.get("event_id") or 0)

        if event_id in (11, 23):
            state.file_events.append((now, event_id, str(event.get("path") or "")))
        elif event_id in (12,13):
            state.registry_events.append((now, event_id, str(event.get("registry") or ""), str(event.get("detail") or ""),))
        elif event_id == 3:
            state.network_events.append((now,event_id,str(event.get("dest") or ""), event.get("port"),))
        elif event_id == 22:
            state.network_events.append((now, event_id, str(event.get("dns") or ""), None,))
        self._prune(state, now)
        return state
    
    def _prune(self, state: ProcessState, now: float) -> None:
        cutoff = now -self.HISTORY_SECONDS

        while state.file_events and state.file_events[0][0] < cutoff:
            state.file_events.popleft()
        while state.network_events and state.network_events[0][0] < cutoff:
            state.network_events.popleft()
        while state.registry_events and state.registry_events[0][0] < cutoff:
            state.registry_events.popleft()

    def attribution_state(self, pid: int) -> ProcessState:
        # The process that acted keeps its own finding. Only a utility hands
        # the finding to whatever launched it, and only for a few steps, so a
        # dropper is still credited for what it told a shell to do
        current = self.ensure(pid)
        seen: Set[int] = {current.pid}

        for _hop in range(self.MAX_HOPS):
            if process_name(current.process) not in self.HELPERS:
                break
            if not current.ppid or current.ppid in seen:
                break

            parent = self.processes.get(current.ppid)
            if parent is None or process_name(parent.process) in self.LAUNCHERS:
                break

            seen.add(current.pid)
            current = parent

        return current
    
    def children_of(self, pid: int) -> Iterable[ProcessState]:
        return (state for state in self.processes.values() if state.ppid == pid)
    
    def process_tree(self, root_pid: int, seen: Optional[Set[int]] = None) -> Dict[str, object]:
        # A reused PID can leave a parent pointing back into its own branch, so
        # each process is only put in the tree once
        seen = set() if seen is None else seen
        root = self.ensure(root_pid)
        seen.add(root.pid)
        children = [child.pid for child in list(self.children_of(root.pid))
                    if child.pid not in seen]
        return {
            "pid": root.pid,
            "process": root.process,
            "children": [self.process_tree(pid, seen) for pid in children],
        }


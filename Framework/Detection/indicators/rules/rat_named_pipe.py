# Detects named pipes opened by a process in a user-writable location

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
)

# Node, Electron and Chromium programs open these constantly. A baseline run
# reported Visual Studio Code for three \uv\ pipes in a few seconds.
RUNTIME_PIPES = (
    "\\uv\\",
    "\\mojo.",
    "\\chrome.",
    "\\crashpad",
    "\\discord-ipc",
    "\\slack",
    "\\pipe\\anonymous",
)

PIPE_EVENTS = {
    17: "created",
    18: "connected to",
}


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Events 17 and 18 record named pipe activity
    event_id = int(event.get("event_id") or 0)
    action = PIPE_EVENTS.get(event_id)
    if action is None:
        return []

    pipe = str(event.get("pipe") or "")
    if not pipe:
        return []
    if any(pipe.lower().startswith(known) for known in RUNTIME_PIPES):
        return []

    process = str(event.get("process") or "").lower()
    if not any(location in process for location in USER_WRITABLE):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="named_pipe_channel",
            description="Process running from a user-writable location %s a named pipe" % action,
            weights={
                "spyware": 0.15,
                "rat": 0.25,
            },
            fingerprint=f"named_pipe:{root_pid}:{pipe}",
            # The pipe name is kept as evidence, but the score lands once
            score_key=f"named_pipe:{root_pid}",
            details={
                "process": event.get("process", ""),
                "pipe": pipe,
                "action": action,
            },
            target_pid=root_pid,
        )
    ]

# Detects one process resolving many different names

from typing import List

from Detection.indicators.base import Finding
from Detection.indicators.rules import rat_history
from Detection.state import ProcessState, StateStore

USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
)

DISTINCT_NAME_THRESHOLD = 8
NAMES_KEPT_AS_EVIDENCE = 12


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 22 records DNS queries
    if int(event.get("event_id") or 0) != 22:
        return []

    name = str(event.get("dns") or "").lower()
    if not name:
        return []

    process = str(event.get("process") or "").lower()
    if not any(location in process for location in USER_WRITABLE):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    names = rat_history.record_dns(store, root_pid, event.get("time") or 0.0, name)

    if len(names) < DISTINCT_NAME_THRESHOLD:
        return []

    return [
        Finding(
            indicator="dns_fanout",
            description="Process running from a user-writable location resolved many different names",
            weights={
                "spyware": 0.10,
                "rat": 0.15,
            },
            fingerprint=f"dns_fanout:{root_pid}",
            details={
                "process": event.get("process", ""),
                "distinct_names": len(names),
                "names": ", ".join(names[:NAMES_KEPT_AS_EVIDENCE]),
            },
            target_pid=root_pid,
        )
    ]

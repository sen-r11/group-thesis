# Detects command and control beaconing at a regular interval

import statistics
from typing import List

from Detection.indicators.base import Finding
from Detection.indicators.rules import rat_history
from Detection.state import ProcessState, StateStore

MIN_CONNECTIONS = 4
MIN_INTERVAL_SECONDS = 5.0
MAX_JITTER = 0.25


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 3 records network connections
    if int(event.get("event_id") or 0) != 3:
        return []

    destination = str(event.get("dest") or "")
    if not destination:
        return []

    try:
        port = int(event.get("port"))
    except (TypeError, ValueError):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    times = rat_history.record_connection(
        store, root_pid, event.get("time") or 0.0, destination, port)

    if len(times) < MIN_CONNECTIONS:
        return []

    gaps = [later - earlier for earlier, later in zip(times, list(times)[1:])]
    gaps = [gap for gap in gaps if gap > 0]
    if len(gaps) < MIN_CONNECTIONS - 1:
        return []

    mean_gap = statistics.mean(gaps)
    if mean_gap < MIN_INTERVAL_SECONDS:
        return []

    # Jitter as a fraction of the mean, so a 30 second and a 300 second
    # beacon are judged the same way
    jitter = statistics.pstdev(gaps) / mean_gap
    if jitter > MAX_JITTER:
        return []

    return [
        Finding(
            indicator="c2_beaconing",
            description="Process contacted one destination repeatedly at a regular interval",
            weights={
                "spyware": 0.15,
                "rat": 0.35,
            },
            fingerprint=f"beacon:{root_pid}:{destination}:{port}",
            score_key=f"beacon:{root_pid}",
            details={
                "process": event.get("process", ""),
                "destination": destination,
                "port": port,
                "connections": len(times),
                "mean_interval_seconds": round(mean_gap, 2),
                "jitter": round(jitter, 3),
            },
            target_pid=root_pid,
        )
    ]

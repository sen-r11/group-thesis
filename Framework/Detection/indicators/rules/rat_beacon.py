# Detects a process keeping a channel open to one outside address

import statistics
from ipaddress import ip_address, ip_network
from typing import List

from Detection.indicators.base import Finding
from Detection.indicators.rules import rat_history
from Detection.state import ProcessState, StateStore

USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

# A check-in opens more than one socket at once, so connections close
# together are counted as one contact rather than several
BURST_SECONDS = 10.0

MIN_CONNECTIONS = 4
MIN_CONTACTS = 4
MIN_SPAN_SECONDS = 60.0

# Real check-in timers are deliberately made uneven, so the interval is
# allowed to vary by a third of itself before it stops counting as a timer
MAX_JITTER = 0.35

LOCAL_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("224.0.0.0/4"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
)


def outside(destination: str) -> bool:
    try:
        address = ip_address(destination)
    except ValueError:
        return False
    if address.is_loopback or address.is_multicast:
        return False
    return not any(address in network for network in LOCAL_NETWORKS)


def contacts(times: List[float]) -> List[float]:
    # One time per contact, keeping the first connection of each burst
    grouped = []
    for moment in sorted(times):
        if not grouped or moment - grouped[-1] > BURST_SECONDS:
            grouped.append(moment)
    return grouped


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 3 records network connections
    if int(event.get("event_id") or 0) != 3:
        return []

    destination = str(event.get("dest") or "")
    if not destination or not outside(destination):
        return []

    # Installed software keeps long running connections as well, so only a
    # process running from somewhere the user can write is reported
    process = str(event.get("process") or "").lower()
    if not any(place in process for place in USER_WRITABLE):
        return []

    try:
        port = int(event.get("port"))
    except (TypeError, ValueError):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    times = rat_history.record_connection(
        store, event.get("process"), event.get("time") or 0.0, destination, port)

    if len(times) < MIN_CONNECTIONS:
        return []

    moments = contacts(list(times))
    span = moments[-1] - moments[0]
    if len(moments) < MIN_CONTACTS or span < MIN_SPAN_SECONDS:
        return []

    gaps = [later - earlier for earlier, later in zip(moments, moments[1:])]
    mean_gap = statistics.mean(gaps)
    if not mean_gap:
        return []

    # Jitter as a fraction of the mean, so a 30 second and a 300 second timer
    # are judged the same way
    jitter = statistics.pstdev(gaps) / mean_gap
    if jitter > MAX_JITTER:
        return []

    return [
        Finding(
            indicator="c2_beaconing",
            description="Process contacted one outside address at a regular interval",
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
                "contacts": len(moments),
                "span_seconds": round(span, 1),
                "mean_interval_seconds": round(mean_gap, 1),
                "jitter": round(jitter, 3),
            },
            target_pid=root_pid,
        )
    ]

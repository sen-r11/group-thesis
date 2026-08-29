# Detects malware asking a public service where the machine it landed on is

from typing import List

from Detection.indicators.base import Finding
from Detection.state import ProcessState, StateStore

USER_WRITABLE = (
    "\\downloads\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\programdata\\",
)

# Services that answer with the address or the country of whoever asked. A
# remote operator uses one to find out what they have caught, so it is one of
# the first things a new implant does
LOOKUP_SERVICES = (
    "ipify.org",
    "ip-api.com",
    "ipinfo.io",
    "icanhazip.com",
    "checkip.amazonaws.com",
    "checkip.dyndns.org",
    "wtfismyip.com",
    "ifconfig.me",
    "ident.me",
    "ipecho.net",
    "myexternalip.com",
    "whatismyipaddress.com",
    "geoiplookup.io",
    "freegeoip.app",
    "ipwhois.app",
    "iplogger.org",
    "db-ip.com",
)


def detect(event: dict, store: StateStore, direct_state: ProcessState) -> List[Finding]:
    # Event 22 records a DNS query
    if int(event.get("event_id") or 0) != 22:
        return []

    name = str(event.get("dns") or "").lower().rstrip(".")
    if not name:
        return []

    service = next((s for s in LOOKUP_SERVICES if name == s or name.endswith("." + s)), None)
    if service is None:
        return []

    # Installed software asks these too. Running from somewhere the user can
    # write is what makes it worth reporting
    process = str(event.get("process") or "").lower()
    if not any(place in process for place in USER_WRITABLE):
        return []

    root_pid = store.attribution_state(direct_state.pid).pid
    return [
        Finding(
            indicator="host_discovery",
            description="Process running from a user-writable location looked up the address of this machine",
            weights={
                "spyware": 0.25,
                "rat": 0.30,
            },
            fingerprint=f"host_discovery:{root_pid}:{service}",
            score_key=f"host_discovery:{root_pid}",
            details={
                "process": event.get("process", ""),
                "service": service,
                "query": event.get("dns", ""),
            },
            target_pid=root_pid,
        )
    ]

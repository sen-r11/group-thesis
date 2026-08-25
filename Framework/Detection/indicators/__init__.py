# List of behavioural rules used by the detection engine

from Detection.indicators.rules import (
    shadow_delete,
    rapid_files,
    suspicious_extensions,
    file_deletion,
    persistence,
    suspicious_process_spawn,
    unusual_parent_child,
    process_injection,
    process_tampering,
    suspicious_network,
    suspicious_dns,
)

DETECTORS = [
    shadow_delete,
    rapid_files,
    suspicious_extensions,
    file_deletion,
    persistence,
    suspicious_process_spawn,
    unusual_parent_child,
    process_injection,
    process_tampering,
    suspicious_network,
    suspicious_dns,
]
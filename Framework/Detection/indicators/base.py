# Common result and weight structure shared by all indicators

from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass
class Finding:
    indicator: str # name of the behaviour that triggered
    description: str # explanation of what happened that can appear in alert
    weights: Dict[str, float] # how much the behaviour contributes to each malware family
    fingerprint: str # unique identifier for the current finding
    details: Dict[str, object] = field(default_factory=dict) # extra evidence about what triggered the rule
    target_pid: Optional[int] = None # pid that should receive the score if a rule targets a specific process
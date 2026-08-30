# Imports all behavioural indicator rules

from Detection.indicators.rules.shadow_delete import detect as shadow_delete
from Detection.indicators.rules.rapid_files import detect as rapid_files
from Detection.indicators.rules.suspicious_extensions import detect as suspicious_extensions
from Detection.indicators.rules.file_deletion import detect as file_deletion
from Detection.indicators.rules.persistence import detect as persistence
from Detection.indicators.rules.suspicious_process_spawn import detect as suspicious_process_spawn
from Detection.indicators.rules.unusual_parent_child import detect as unusual_parent_child
from Detection.indicators.rules.process_injection import detect as process_injection
from Detection.indicators.rules.process_tampering import detect as process_tampering
from Detection.indicators.rules.suspicious_network import detect as suspicious_network
from Detection.indicators.rules.suspicious_dns import detect as suspicious_dns

# RAT indicators (Kai), sections 2.7.4 to 2.7.7
from Detection.indicators.rules.rat_beacon import detect as rat_beacon
from Detection.indicators.rules.rat_scheduled_task import detect as rat_scheduled_task
from Detection.indicators.rules.rat_named_pipe import detect as rat_named_pipe
from Detection.indicators.rules.rat_privileged_access import detect as rat_privileged_access
from Detection.indicators.rules.rat_dns_fanout import detect as rat_dns_fanout
from Detection.indicators.rules.rat_remote_shell import detect as rat_remote_shell
from Detection.indicators.rules.rat_uac_bypass import detect as rat_uac_bypass
from Detection.indicators.rules.rat_host_discovery import detect as rat_host_discovery

# Spyware additional indicator
from Detection.indicators.rules.spyware_collection import detect as spyware_collection
from Detection.indicators.rules.spyware_staging import detect as spyware_staging

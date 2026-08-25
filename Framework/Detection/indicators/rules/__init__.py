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
"""Direct/Reject proxy parser for Surge format."""
from typing import List, Optional
from ....models.node import Proxy
from .registry import surge_protocol_registry


@surge_protocol_registry.register('direct', 'reject', 'reject-tinygif')
def parse(name: str, server: str, port: int, params: List[str]) -> Optional[Proxy]:
    """Parse Direct/Reject proxy - these are not real proxies."""
    # Direct and Reject are special built-in proxies in Surge
    # We don't create nodes for them
    return None
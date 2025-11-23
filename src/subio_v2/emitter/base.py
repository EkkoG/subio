from abc import ABC, abstractmethod
from typing import List, Any
from subio_v2.model.nodes import Node


class BaseEmitter(ABC):
    @abstractmethod
    def emit(self, nodes: List[Node]) -> Any:
        """
        Emit nodes to a specific format.
        Returns dict (for structure) or str (for text).
        """
        pass

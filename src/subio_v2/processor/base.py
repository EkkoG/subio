from abc import ABC, abstractmethod
from typing import List
from src.subio_v2.model.nodes import Node

class Processor(ABC):
    @abstractmethod
    def process(self, nodes: List[Node]) -> List[Node]:
        pass


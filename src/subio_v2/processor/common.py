import re
from typing import List, Dict
from subio_v2.processor.base import Processor
from subio_v2.model.nodes import Node


class FilterProcessor(Processor):
    def __init__(self, include: str = None, exclude: str = None):
        self.include = re.compile(include) if include else None
        self.exclude = re.compile(exclude) if exclude else None

    def process(self, nodes: List[Node]) -> List[Node]:
        result = []
        for node in nodes:
            if self.exclude and self.exclude.search(node.name):
                continue
            if self.include and not self.include.search(node.name):
                continue
            result.append(node)
        return result


class RenameProcessor(Processor):
    def __init__(
        self, prefix: str = "", suffix: str = "", replace: List[Dict[str, str]] = None
    ):
        self.prefix = prefix
        self.suffix = suffix
        self.replace = replace or []

    def process(self, nodes: List[Node]) -> List[Node]:
        for node in nodes:
            name = node.name

            # Replacements
            for item in self.replace:
                old = item.get("old")
                new = item.get("new")
                if old and new is not None:
                    name = name.replace(old, new)

            # Prefix/Suffix
            node.name = f"{self.prefix}{name}{self.suffix}"

        return nodes

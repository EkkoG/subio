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
            # Use original_name if available, otherwise use current name
            name_to_match = node.original_name if node.original_name is not None else node.name

            if self.exclude and self.exclude.search(name_to_match):
                continue
            if self.include and not self.include.search(name_to_match):
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
            # Save original name before any modifications (only if not already saved)
            if node.original_name is None:
                node.original_name = node.name

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

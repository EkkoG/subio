from __future__ import annotations

import re
from collections.abc import Iterable

from subio_v2.core.nodes import Node
from subio_v2.workflow.config import FilterConfig, RenameConfig


def filter_nodes(nodes: list[Node], config: FilterConfig | None) -> list[Node]:
    if config is None:
        return nodes
    include = re.compile(config.include) if config.include else None
    exclude = re.compile(config.exclude) if config.exclude else None
    result: list[Node] = []
    for node in nodes:
        name = node.original_name if node.original_name is not None else node.name
        if exclude and exclude.search(name):
            continue
        if include and not include.search(name):
            continue
        result.append(node)
    return result


def rename_nodes(nodes: list[Node], config: RenameConfig) -> list[Node]:
    renamed: dict[str, str] = {}
    rules = [
        (re.compile(rule.old) if rule.regex else rule.old, rule.new)
        for rule in config.replace
    ]
    for node in nodes:
        if node.original_name is None:
            node.original_name = node.name
        name = node.name
        for pattern, replacement in rules:
            if isinstance(pattern, re.Pattern):
                name = pattern.sub(replacement, name)
            elif pattern:
                name = name.replace(pattern, replacement)
        old_name = node.name
        node.name = f"{config.add_prefix}{name}{config.suffix}"
        renamed[old_name] = node.name

    for node in nodes:
        if node.dialer_proxy in renamed:
            node.dialer_proxy = renamed[node.dialer_proxy]
    return nodes


def set_dialer_proxy(nodes: Iterable[Node], dialer_proxy: str) -> list[Node]:
    result = list(nodes)
    for node in result:
        node.dialer_proxy = dialer_proxy
    return result

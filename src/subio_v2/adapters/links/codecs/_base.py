import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from subio_v2.core.nodes import Node, Protocol

LinkParser = Callable[[str], Node | None]


@dataclass(frozen=True)
class LinkCodec:
    protocol: Protocol
    targets: frozenset[str]
    build: Callable[[Node], str | None]
    schemes: frozenset[str] = frozenset()
    parse: LinkParser | None = None
    target_constraints: Mapping[str, Mapping[str, Any]] = MappingProxyType({})


def quote_name(name: str) -> str:
    return urllib.parse.quote(name, safe="")

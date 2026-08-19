import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from subio_v2.model.nodes import Node, Protocol


@dataclass(frozen=True)
class LinkCodec:
    protocol: Protocol
    targets: frozenset[str]
    build: Callable[[Node], str | None]


def quote_name(name: str) -> str:
    return urllib.parse.quote(name, safe="")

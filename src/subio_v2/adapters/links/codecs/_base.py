import ipaddress
import re
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


class LinkAuthorityError(ValueError):
    field = "server"
    code = "conversion.invalid-value"


def format_authority(server: str, port: int) -> str:
    if ":" in server or "[" in server or "]" in server:
        address = (
            server[1:-1] if server.startswith("[") and server.endswith("]") else server
        )
        try:
            if "%" in address:
                raise ValueError("Scoped IPv6 is not represented by this link codec")
            ipaddress.IPv6Address(address)
        except ValueError as exc:
            raise LinkAuthorityError("Server is not a representable URI host") from exc
        host = f"[{address}]"
    # Restrict reg-name hosts to URI unreserved characters; never decode host escapes.
    elif re.fullmatch(r"[A-Za-z0-9._~-]+", server):
        host = server
    else:
        raise LinkAuthorityError("Server is not a representable URI host")
    return f"{host}:{port}"

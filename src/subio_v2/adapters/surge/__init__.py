"""Shared Surge syntax primitives."""

from subio_v2.adapters.surge.syntax import (
    SurgeParameter,
    SurgeParameters,
    SurgeProxyRecord,
    parse_proxy_line,
    serialize_proxy_line,
)

__all__ = [
    "SurgeParameter",
    "SurgeParameters",
    "SurgeProxyRecord",
    "parse_proxy_line",
    "serialize_proxy_line",
]

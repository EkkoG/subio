"""sing-box node adapters."""

from subio_v2.adapters.singbox.codecs import (
    SINGBOX_ENDPOINT_CODECS,
    SINGBOX_OUTBOUND_CODECS,
    encode_endpoint,
    encode_outbound,
)
from subio_v2.adapters.singbox.parser import SingBoxParser

__all__ = [
    "SINGBOX_ENDPOINT_CODECS",
    "SINGBOX_OUTBOUND_CODECS",
    "SingBoxParser",
    "encode_endpoint",
    "encode_outbound",
]

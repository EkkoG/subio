"""sing-box node adapters."""

from subio_v2.adapters.singbox.outbound import (
    SINGBOX_OUTBOUND_CODECS,
    encode_outbound,
)
from subio_v2.adapters.singbox.parser import SingBoxParser

__all__ = ["SINGBOX_OUTBOUND_CODECS", "SingBoxParser", "encode_outbound"]

from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _emit_no_fields,
)
from subio_v2.core.nodes import (
    DirectNode,
    Protocol,
)


def _parse_direct(data: dict[str, Any]) -> dict[str, Any]:
    return {}


CODEC = SingBoxOutboundCodec(
    "direct",
    Protocol.DIRECT,
    DirectNode,
    frozenset(),
    frozenset(),
    parse_fields=_parse_direct,
    emit_fields=_emit_no_fields,
    endpoint=False,
)
